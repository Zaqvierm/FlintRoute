package writebudget

import (
	"sync"
	"sync/atomic"
	"time"
)

type Counters struct {
	FilesCreated  uint64    `json:"files_created"`
	FilesReplaced uint64    `json:"files_replaced"`
	FilesDeleted  uint64    `json:"files_deleted"`
	BytesWritten  uint64    `json:"bytes_written"`
	Fsyncs        uint64    `json:"fsyncs"`
	Snapshots     uint64    `json:"snapshots"`
	Backups       uint64    `json:"backups"`
	LastReason    string    `json:"last_reason,omitempty"`
	LastAt        time.Time `json:"last_at,omitempty"`
}

var (
	filesCreated  atomic.Uint64
	filesReplaced atomic.Uint64
	filesDeleted  atomic.Uint64
	bytesWritten  atomic.Uint64
	fsyncs        atomic.Uint64
	snapshots     atomic.Uint64
	backups       atomic.Uint64
	lastMu        sync.RWMutex
	lastReason    string
	lastAt        time.Time
)

func RecordFileWrite(created bool, bytes, fsyncCount uint64, reason string) {
	if created {
		filesCreated.Add(1)
	} else {
		filesReplaced.Add(1)
	}
	bytesWritten.Add(bytes)
	fsyncs.Add(fsyncCount)
	recordReason(reason)
}

func RecordDelete(reason string) {
	filesDeleted.Add(1)
	recordReason(reason)
}

func RecordSnapshot(reason string) {
	snapshots.Add(1)
	recordReason(reason)
}

func RecordBackup(reason string) {
	backups.Add(1)
	recordReason(reason)
}

func Snapshot() Counters {
	result := Counters{
		FilesCreated: filesCreated.Load(), FilesReplaced: filesReplaced.Load(), FilesDeleted: filesDeleted.Load(),
		BytesWritten: bytesWritten.Load(), Fsyncs: fsyncs.Load(), Snapshots: snapshots.Load(), Backups: backups.Load(),
	}
	lastMu.RLock()
	result.LastReason, result.LastAt = lastReason, lastAt
	lastMu.RUnlock()
	return result
}

func recordReason(reason string) {
	lastMu.Lock()
	lastReason = reason
	lastAt = time.Now().UTC()
	lastMu.Unlock()
}
