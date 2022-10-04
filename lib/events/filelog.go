/*
Copyright 2018-2019 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package events

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gravitational/teleport"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/session"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	log "github.com/sirupsen/logrus"
)

// FileLogConfig is a configuration for file log
type FileLogConfig struct {
	// RotationPeriod defines how frequently to rotate the log file
	RotationPeriod time.Duration
	// Dir is a directory where logger puts the files
	Dir string
	// SymlinkDir is a directory for symlink pointer to the current log
	SymlinkDir string
	// Clock is a clock interface, used in tests
	Clock clockwork.Clock
	// UIDGenerator is used to generate unique IDs for events
	UIDGenerator utils.UID
	// SearchDirs is a function that returns
	// search directories, if not set, only Dir is used
	SearchDirs func() ([]string, error)
	// MaxScanTokenSize define maximum line entry size.
	MaxScanTokenSize int
}

// CheckAndSetDefaults checks and sets config defaults
func (cfg *FileLogConfig) CheckAndSetDefaults() error {
	if cfg.Dir == "" {
		return trace.BadParameter("missing parameter Dir")
	}
	if !utils.IsDir(cfg.Dir) {
		return trace.BadParameter("path %q does not exist or is not a directory", cfg.Dir)
	}
	if cfg.SymlinkDir == "" {
		cfg.SymlinkDir = cfg.Dir
	}
	if !utils.IsDir(cfg.SymlinkDir) {
		return trace.BadParameter("path %q does not exist or is not a directory", cfg.SymlinkDir)
	}
	if cfg.RotationPeriod == 0 {
		cfg.RotationPeriod = defaults.LogRotationPeriod
	}
	if cfg.RotationPeriod%(24*time.Hour) != 0 {
		return trace.BadParameter("rotation period %v is not a multiple of 24 hours, e.g. '24h' or '48h'", cfg.RotationPeriod)
	}
	if cfg.Clock == nil {
		cfg.Clock = clockwork.NewRealClock()
	}
	if cfg.UIDGenerator == nil {
		cfg.UIDGenerator = utils.NewRealUID()
	}
	if cfg.MaxScanTokenSize == 0 {
		cfg.MaxScanTokenSize = bufio.MaxScanTokenSize
	}
	return nil
}

// NewFileLog returns a new instance of a file log
func NewFileLog(cfg FileLogConfig) (*FileLog, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	f := &FileLog{
		FileLogConfig: cfg,
		Entry: log.WithFields(log.Fields{
			trace.Component: teleport.ComponentAuditLog,
		}),
	}
	return f, nil
}

// FileLog is a file local audit events log,
// logs all events to the local file in json encoded form
type FileLog struct {
	*log.Entry
	FileLogConfig
	// rw protects the file from rotation during concurrent
	// event emission.
	rw sync.RWMutex
	// file is the current global event log file. As the time goes
	// on, it will be replaced by a new file every day.
	file *os.File
	// fileTime is a rounded (to a day, by default) timestamp of the
	// currently opened file
	fileTime time.Time
}

// EmitAuditEvent adds a new event to the log.
func (l *FileLog) EmitAuditEvent(ctx context.Context, event apievents.AuditEvent) error {
	l.rw.RLock()
	defer l.rw.RUnlock()

	// see if the log needs to be rotated
	if l.mightNeedRotation() {
		// log might need rotation; switch to write-lock
		// to avoid rotating during concurrent event emission.
		l.rw.RUnlock()
		l.rw.Lock()

		// perform rotation if still necessary (rotateLog rechecks the
		// requirements internally, since rotation may have been performed
		// during our switch from read to write locks)
		err := l.rotateLog()

		// switch back to read lock
		l.rw.Unlock()
		l.rw.RLock()
		if err != nil {
			log.Error(err)
		}
	}

	// line is the text to be logged
	line, err := utils.FastMarshal(event)
	if err != nil {
		return trace.Wrap(err)
	}
	if l.file == nil {
		return trace.NotFound(
			"file log is not found due to permission or disk issue")
	}

	if len(line) > l.MaxScanTokenSize {
		switch {
		case canReduceMessageSize(event):
			line, err = l.trimSizeAndMarshal(event)
			if err != nil {
				return trace.Wrap(err)
			}
		default:
			fields := log.Fields{"event_type": event.GetType(), "event_size": len(line)}
			l.WithFields(fields).Warnf("Got a event that exeeded max allowed size.")
			return trace.BadParameter("event size %q exceeds max entry size %q", len(line), l.MaxScanTokenSize)
		}
	}

	// log it to the main log file:
	_, err = fmt.Fprintln(l.file, string(line))
	return trace.ConvertSystemError(err)
}

func canReduceMessageSize(event apievents.AuditEvent) bool {
	_, ok := event.(messageSizeTrimmer)
	return ok
}

func (l *FileLog) trimSizeAndMarshal(event apievents.AuditEvent) ([]byte, error) {
	s, ok := event.(messageSizeTrimmer)
	if !ok {
		return nil, trace.BadParameter("invalid event type %T", event)
	}
	sEvent := s.TrimToMaxSize(l.MaxScanTokenSize)
	line, err := utils.FastMarshal(sEvent)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if len(line) > l.MaxScanTokenSize {
		return nil, trace.BadParameter("event %T reached max FileLog entry size limit", event.Size())
	}
	return line, nil
}

type messageSizeTrimmer interface {
	TrimToMaxSize(int) apievents.AuditEvent
}

// Close closes the audit log, which includes closing all file handles and
// releasing all session loggers.
func (l *FileLog) Close() error {
	l.rw.Lock()
	defer l.rw.Unlock()

	var err error
	if l.file != nil {
		err = l.file.Close()
		l.file = nil
	}
	return err
}

// mightNeedRotation checks if the current log file looks older than a given duration,
// used by rotateLog to decide if it should acquire a write lock.  Must be called under
// read lock.
func (l *FileLog) mightNeedRotation() bool {

	if l.file == nil {
		return true
	}

	// determine the timestamp for the current log file rounded to the day.
	fileTime := l.Clock.Now().UTC().Truncate(24 * time.Hour)

	return l.fileTime.Before(fileTime)
}

// rotateLog checks if the current log file is older than a given duration,
// and if it is, closes it and opens a new one.  Must be called under write lock.
func (l *FileLog) rotateLog() (err error) {

	// determine the timestamp for the current log file rounded to the day.
	fileTime := l.Clock.Now().UTC().Truncate(24 * time.Hour)

	logFilename := filepath.Join(l.Dir,
		fileTime.Format(defaults.AuditLogTimeFormat)+LogfileExt)

	openLogFile := func() error {
		l.file, err = os.OpenFile(logFilename, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0640)
		if err != nil {
			log.Error(err)
		}
		l.fileTime = fileTime
		return trace.Wrap(err)
	}

	linkFilename := filepath.Join(l.SymlinkDir, SymlinkFilename)
	createSymlink := func() error {
		err = trace.ConvertSystemError(os.Remove(linkFilename))
		if err != nil {
			if !trace.IsNotFound(err) {
				return trace.Wrap(err)
			}
		}
		return trace.ConvertSystemError(os.Symlink(logFilename, linkFilename))
	}

	// need to create a log file?
	if l.file == nil {
		if err := openLogFile(); err != nil {
			return trace.Wrap(err)
		}
		return trace.Wrap(createSymlink())
	}

	// time to advance the logfile?
	if l.fileTime.Before(fileTime) {
		l.file.Close()
		if err := openLogFile(); err != nil {
			return trace.Wrap(err)
		}
		return trace.Wrap(createSymlink())
	}
	return nil
}

// StreamSessionEvents streams all events from a given session recording. An error is returned on the first
// channel if one is encountered. Otherwise the event channel is closed when the stream ends.
// The event channel is not closed on error to prevent race conditions in downstream select statements.
func (l *FileLog) StreamSessionEvents(ctx context.Context, sessionID session.ID, startIndex int64) (chan apievents.AuditEvent, chan error) {
	c, e := make(chan apievents.AuditEvent), make(chan error, 1)
	e <- trace.NotImplemented("not implemented")
	return c, e
}

// ByTimeAndIndex sorts events by time extracting timestamp from JSON field
// and if there are several session events with the same session
// by event index, regardless of the time
type ByTimeAndIndex []EventFields

func (f ByTimeAndIndex) Len() int {
	return len(f)
}

func (f ByTimeAndIndex) Less(i, j int) bool {
	itime := getTime(f[i][EventTime])
	jtime := getTime(f[j][EventTime])
	if itime.Equal(jtime) && f[i][SessionEventID] == f[j][SessionEventID] {
		return getEventIndex(f[i][EventIndex]) < getEventIndex(f[j][EventIndex])
	}
	return itime.Before(jtime)
}

func (f ByTimeAndIndex) Swap(i, j int) {
	f[i], f[j] = f[j], f[i]
}

// getTime converts json time to string
func getTime(v interface{}) time.Time {
	sval, ok := v.(string)
	if !ok {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, sval)
	if err != nil {
		return time.Time{}
	}
	return t
}

func getEventIndex(v interface{}) float64 {
	switch val := v.(type) {
	case float64:
		return val
	}
	return 0
}
