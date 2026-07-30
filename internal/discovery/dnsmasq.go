package discovery

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
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
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		next, reset, err := w.readFrom(ctx, offset, maxBytes)
		if err == nil {
			offset = next
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
	info, err := os.Lstat(w.Path)
	if err != nil {
		return offset, false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return offset, false, errors.New("DNS observation log is not a regular file")
	}
	if info.Size() < offset {
		offset = 0
	}
	file, err := os.Open(w.Path)
	if err != nil {
		return offset, false, err
	}
	if offset > 0 {
		var boundary [1]byte
		if _, err := file.ReadAt(boundary[:], offset-1); err != nil || boundary[0] != '\n' {
			offset = 0
		}
	}
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		_ = file.Close()
		return offset, false, err
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
		return offset, false, err
	}
	if seekErr != nil {
		return offset, false, seekErr
	}
	if closeErr != nil {
		return offset, false, closeErr
	}
	if info.Size() > maxBytes {
		if err := os.Truncate(w.Path, 0); err != nil {
			return position, false, err
		}
		return 0, true, nil
	}
	return position, false, nil
}
