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

type Observation struct {
	Domain    string `json:"domain"`
	QueryType string `json:"query_type"`
	Client    string `json:"-"`
}

type Watcher struct {
	Path         string
	PollInterval time.Duration
	MaxBytes     int64
	Emit         func(context.Context, Observation)
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
	if (identity != "" && previousIdentity != "" && identity != previousIdentity) || info.Size() < offset {
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
	scanner := bufio.NewScanner(io.LimitReader(file, maxBytes+1))
	scanner.Buffer(make([]byte, 4096), 128<<10)
	for scanner.Scan() {
		if observation, ok := ParseDNSMasqLine(scanner.Text()); ok {
			w.Emit(ctx, observation)
		}
	}
	position, seekErr := file.Seek(0, io.SeekCurrent)
	closeErr := file.Close()
	if err := scanner.Err(); err != nil {
		return offset, false, identity, err
	}
	if seekErr != nil {
		return offset, false, identity, seekErr
	}
	if closeErr != nil {
		return offset, false, identity, closeErr
	}
	// The reader is not allowed to truncate a file owned by dnsmasq.  Rotation
	// or truncation is detected on the next pass by size/boundary checks; an
	// external writer remains the sole owner of its inode.  Keep the cursor at
	// the bytes actually consumed so an oversized log is drained in bounded
	// chunks without replaying or destroying the writer's data.
	return position, false, identity, nil
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
