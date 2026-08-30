package discovery

import (
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

// A malformed line is drained only up to this bounded amount. Once the cap is
// reached the tail is discarded and the cursor advances, so a writer that
// never emits a newline cannot pin the watcher forever.
const maxObservationDrainBytes = 8 << 20

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
	// Runtime-only state for an oversized unterminated record that was
	// explicitly discarded. This prevents boundary validation from rewinding
	// the same malformed tail on every poll.
	discardedUntil    int64
	discardedIdentity string
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

func (w *Watcher) Run(ctx context.Context) error {
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
		next, _, nextIdentity, err := w.readFromWithIdentity(ctx, offset, maxBytes, identity)
		if err == nil {
			offset = next
			identity = nextIdentity
			// readFromWithIdentity already rewinds internally when the inode
			// rotates or the writer truncates the file.  Rewinding again here
			// would replay the replacement tail on every poll.
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

func (w *Watcher) readFrom(ctx context.Context, offset, maxBytes int64) (int64, bool, error) {
	next, reset, _, err := w.readFromWithIdentity(ctx, offset, maxBytes, "")
	return next, reset, err
}

func (w *Watcher) readFromWithIdentity(ctx context.Context, offset, maxBytes int64, previousIdentity string) (int64, bool, string, error) {
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
		w.discardedUntil = 0
		w.discardedIdentity = ""
	}
	file, err := os.Open(w.Path)
	if err != nil {
		return offset, false, identity, err
	}
	allowDiscardedBoundary := offset > 0 && w.discardedIdentity == identity && offset == w.discardedUntil
	if offset > 0 && !allowDiscardedBoundary {
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
	// Read with a fixed-size buffer. The pass budget applies to ordinary
	// records; an oversized record is drained past that budget only until its
	// newline (or a bounded drain cap) so its cursor can never remain pinned.
	buffer := make([]byte, 64<<10)
	var consumed int64
	var completePosition int64
	var emitted uint64
	var lineBytes int64
	var line []byte
	overlong := false
	for {
		if !overlong && consumed >= maxBytes {
			break
		}
		want := int64(len(buffer))
		if !overlong && maxBytes-consumed < want {
			want = maxBytes - consumed
		}
		if want <= 0 {
			break
		}
		n, readErr := file.Read(buffer[:want])
		if n > 0 {
			chunkStart := consumed
			consumed += int64(n)
			for index, b := range buffer[:n] {
				if b == '\n' {
					if !overlong {
						if observation, ok := ParseDNSMasqLine(string(line)); ok {
							w.Emit(ctx, observation)
							emitted++
						}
					}
					line = line[:0]
					lineBytes = 0
					completePosition = chunkStart + int64(index) + 1
					if overlong {
						overlong = false
						// A line that required draining beyond the normal budget is
						// the end of this bounded pass; the next pass starts after it.
						if consumed > maxBytes {
							break
						}
					}
					continue
				}
				lineBytes++
				if !overlong {
					if len(line) < maxObservationLineBytes {
						line = append(line, b)
					} else {
						overlong = true
						line = line[:0]
					}
				}
			}
			if overlong && lineBytes >= maxObservationDrainBytes {
				// No newline within the drain cap: discard this malformed tail
				// rather than re-reading it forever on every poll.
				completePosition = consumed
				w.discardedUntil = offset + completePosition
				w.discardedIdentity = identity
				break
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				if overlong {
					// An unterminated oversized record is malformed; discard the
					// consumed tail and make progress to EOF.
					completePosition = consumed
					w.discardedUntil = offset + completePosition
					w.discardedIdentity = identity
				}
				break
			}
			_ = file.Close()
			return offset, reset, identity, readErr
		}
	}
	closeErr := file.Close()
	if closeErr != nil {
		return offset, reset, identity, closeErr
	}
	// Only complete records advance the cursor. Oversized malformed tails are
	// explicitly discarded, while an ordinary partial line remains pinned until
	// its continuation arrives.
	position := offset + completePosition
	if completePosition == 0 && consumed == 0 {
		position = offset
	}
	if w.Progress != nil {
		w.Progress(position, emitted)
	}
	if w.discardedIdentity == identity && position > w.discardedUntil {
		w.discardedUntil = 0
		w.discardedIdentity = ""
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
