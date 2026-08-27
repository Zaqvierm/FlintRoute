package discovery

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"time"

	"router-policy/internal/tspu"
)

const MaxObservationLogBytes int64 = 1 << 20

// maxObservationLineBytes prevents one corrupt/hostile log line from growing
// the reader buffer without bound. Oversized lines are drained and discarded
// once their terminating newline is seen.
const maxObservationLineBytes = 128 << 10

type Observation struct {
	Domain    string `json:"domain"`
	QueryType string `json:"query_type"`
	Client    string `json:"-"`
}

type Watcher struct {
	Path         string
	PollInterval time.Duration
	MaxBytes     int64
	// StartAtEnd prevents a controller restart from replaying the entire
	// historical dnsmasq log.  Callers that intentionally need a fixture or
	// bounded replay can leave it false.
	StartAtEnd bool
	Emit       func(context.Context, Observation)
	// Progress is called after each bounded pass with the durable cursor and
	// number of emitted records. It is intentionally observational only.
	Progress func(cursor int64, emitted uint64)
}

func ParseDNSMasqLine(line string) (Observation, bool) {
	fields := strings.Fields(strings.TrimSpace(line))
	for index, field := range fields {
		if !strings.HasPrefix(field, "query[") || !strings.HasSuffix(field, "]") || index+3 >= len(fields) || fields[index+2] != "from" {
			continue
		}
		queryType := strings.TrimSuffix(strings.TrimPrefix(field, "query["), "]")
		if queryType != "A" && queryType != "AAAA" && queryType != "HTTPS" {
			return Observation{}, false
		}
		domain, err := tspu.NormalizeDomain(strings.TrimSuffix(fields[index+1], "."))
		if err != nil || strings.HasSuffix(domain, ".arpa") {
			return Observation{}, false
		}
		return Observation{Domain: domain, QueryType: queryType, Client: fields[index+3]}, true
	}
	return Observation{}, false
}

func (w Watcher) Run(ctx context.Context) error {
	if w.Path == "" || w.Emit == nil {
		return errors.New("DNS observation path and callback are required")
	}
	interval := w.PollInterval
	if interval <= 0 {
		interval = time.Second
	}
	maxBytes := w.MaxBytes
	if maxBytes <= 0 || maxBytes > MaxObservationLogBytes {
		maxBytes = MaxObservationLogBytes
	}
	var offset int64
	var identity string
	if w.StartAtEnd {
		info, err := os.Lstat(w.Path)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
				return errors.New("DNS observation log is not a regular file")
			}
			offset = info.Size()
			identity = observationFileIdentity(info)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		next, reset, nextIdentity, err := w.readFromWithIdentity(ctx, offset, maxBytes, identity)
		if err == nil {
			offset = next
			identity = nextIdentity
			if reset {
				offset = 0
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (w Watcher) readFrom(ctx context.Context, offset, maxBytes int64) (int64, bool, error) {
	next, reset, _, err := w.readFromWithIdentity(ctx, offset, maxBytes, "")
	return next, reset, err
}

func (w Watcher) readFromWithIdentity(ctx context.Context, offset, maxBytes int64, previousIdentity string) (int64, bool, string, error) {
	info, err := os.Lstat(w.Path)
	if err != nil {
		return offset, false, previousIdentity, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return offset, false, previousIdentity, errors.New("DNS observation log is not a regular file")
	}
	identity := observationFileIdentity(info)
	reset := (identity != "" && previousIdentity != "" && identity != previousIdentity) || info.Size() < offset
	if reset {
		offset = 0
	}
	file, err := os.Open(w.Path)
	if err != nil {
		return offset, false, identity, err
	}
	if offset > 0 {
		var boundary [1]byte
		if _, err := file.ReadAt(boundary[:], offset-1); err != nil || boundary[0] != '\n' {
			offset = 0
		}
	}
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		_ = file.Close()
		return offset, false, identity, err
	}
	if maxBytes <= 0 {
		maxBytes = MaxObservationLogBytes
	}
	// Cap normal work at maxBytes. A pathological line can be larger than one
	// bounded pass, so once it is known to be oversized we replace this limited
	// reader with a direct fixed-size reader and drain only that line to its
	// newline. This keeps memory bounded while allowing the cursor to advance
	// only after a complete record.
	limited := &io.LimitedReader{R: file, N: maxBytes}
	reader := bufio.NewReaderSize(limited, 64<<10)
	var consumed int64
	var emitted uint64
	var lineBytes int64
	var line []byte
	overlong := false
	for consumed < maxBytes || overlong {
		fragment, readErr := reader.ReadSlice('\n')
		consumed += int64(len(fragment))
		lineBytes += int64(len(fragment))
		if len(line)+len(fragment) <= maxObservationLineBytes {
			line = append(line, fragment...)
		} else {
			overlong = true
		}
		complete := len(fragment) > 0 && fragment[len(fragment)-1] == '\n'
		if complete {
			if !overlong {
				if observation, ok := ParseDNSMasqLine(strings.TrimSuffix(string(line), "\n")); ok {
					w.Emit(ctx, observation)
					emitted++
				}
			}
			line = line[:0]
			lineBytes = 0
			overlong = false
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				if overlong && !complete && consumed >= maxBytes {
					// The pass budget ended in the middle of an oversized line.
					// Continue from the same file position without retaining the
					// line in memory; the next ReadSlice will find its newline.
					reader = bufio.NewReaderSize(file, 64<<10)
					continue
				}
				break
			}
			if errors.Is(readErr, bufio.ErrBufferFull) {
				if consumed >= maxBytes {
					if overlong {
						reader = bufio.NewReaderSize(file, 64<<10)
						continue
					}
					break
				}
				continue
			}
			_ = file.Close()
			return offset, reset, identity, readErr
		}
		if !complete {
			if overlong && consumed >= maxBytes {
				// Keep draining an oversized record beyond the normal pass budget;
				// otherwise its newline can never be observed and the cursor would
				// remain pinned at the same offset on every poll.
				continue
			}
			// EOF or the bounded pass ended in the middle of a line. Do not
			// advance the durable cursor: the next pass will reread this
			// partial line together with its continuation.
			break
		}
	}
	closeErr := file.Close()
	if closeErr != nil {
		return offset, reset, identity, closeErr
	}
	// Only complete newline-terminated records advance the cursor. If the
	// bounded pass ended inside a line, consumed includes that partial fragment
	// but it must not be persisted or the next pass would either duplicate or
	// skip data. A complete record is allowed to end exactly at maxBytes.
	position := offset + consumed
	if lineBytes > 0 {
		position -= lineBytes
	}
	if w.Progress != nil {
		w.Progress(position, emitted)
	}
	return position, reset, identity, nil
}

// observationFileIdentity returns the stable device/inode pair on Unix-like
// filesystems.  Some host platforms do not expose those fields through
// os.FileInfo; there the existing size/boundary checks remain the fallback.
func observationFileIdentity(info os.FileInfo) string {
	if info == nil || info.Sys() == nil {
		return ""
	}
	value := reflect.ValueOf(info.Sys())
	for value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return ""
		}
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		return ""
	}
	dev, ino := value.FieldByName("Dev"), value.FieldByName("Ino")
	if !dev.IsValid() || !ino.IsValid() || !dev.CanInterface() || !ino.CanInterface() {
		return ""
	}
	return fmt.Sprintf("%v:%v", dev.Interface(), ino.Interface())
}
