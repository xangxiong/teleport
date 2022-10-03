/*
Copyright 2015-2020 Gravitational, Inc.

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
	"context"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	log "github.com/sirupsen/logrus"

	"github.com/gravitational/teleport"
	apidefaults "github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/session"
	"github.com/gravitational/teleport/lib/utils"
)

const (
	// SessionLogsDir is a subdirectory inside the eventlog data dir
	// where all session-specific logs and streams are stored, like
	// in /var/lib/teleport/log/sessions
	SessionLogsDir = "sessions"

	// StreamingLogsDir is a subdirectory of sessions /var/lib/teleport/log/streaming
	// is used in new versions of the uploader
	StreamingLogsDir = "streaming"

	// RecordsDir is a subdirectory with default records /var/lib/teleport/log/records
	// is used in new versions of the uploader
	RecordsDir = "records"

	// PlaybackDir is a directory for playbacks
	PlaybackDir = "playbacks"

	// LogfileExt defines the ending of the daily event log file
	LogfileExt = ".log"

	// SymlinkFilename is a name of the symlink pointing to the last
	// current log file
	SymlinkFilename = "events.log"
)

// AuditLog is a new combined facility to record Teleport events and
// sessions. It implements IAuditLog
type AuditLog struct {
	sync.RWMutex
	AuditLogConfig

	// log specifies the logger
	log log.FieldLogger

	// playbackDir is a directory used for unpacked session recordings
	playbackDir string

	// activeDownloads helps to serialize simultaneous downloads
	// from the session record server
	activeDownloads map[string]context.Context

	// ctx signals close of the audit log
	ctx context.Context

	// cancel triggers closing of the signal context
	cancel context.CancelFunc

	// localLog is a local events log used
	// to emit audit events if no external log has been specified
	localLog *FileLog
}

// AuditLogConfig specifies configuration for AuditLog server
type AuditLogConfig struct {
	// DataDir is the directory where audit log stores the data
	DataDir string

	// ServerID is the id of the audit log server
	ServerID string

	// RotationPeriod defines how frequently to rotate the log file
	RotationPeriod time.Duration

	// Clock is a clock either real one or used in tests
	Clock clockwork.Clock

	// UIDGenerator is used to generate unique IDs for events
	UIDGenerator utils.UID

	// GID if provided will be used to set group ownership of the directory
	// to GID
	GID *int

	// UID if provided will be used to set userownership of the directory
	// to UID
	UID *int

	// DirMask if provided will be used to set directory mask access
	// otherwise set to default value
	DirMask *os.FileMode

	// PlaybackRecycleTTL is a time after uncompressed playback files will be
	// deleted
	PlaybackRecycleTTL time.Duration

	// UploadHandler is a pluggable external upload handler,
	// used to fetch sessions from external sources
	UploadHandler MultipartHandler

	// ExternalLog is a pluggable external log service
	ExternalLog IAuditLog

	// Context is audit log context
	Context context.Context
}

// CheckAndSetDefaults checks and sets defaults
func (a *AuditLogConfig) CheckAndSetDefaults() error {
	if a.DataDir == "" {
		return trace.BadParameter("missing parameter DataDir")
	}
	if a.ServerID == "" {
		return trace.BadParameter("missing parameter ServerID")
	}
	if a.UploadHandler == nil {
		return trace.BadParameter("missing parameter UploadHandler")
	}
	if a.Clock == nil {
		a.Clock = clockwork.NewRealClock()
	}
	if a.UIDGenerator == nil {
		a.UIDGenerator = utils.NewRealUID()
	}
	if a.RotationPeriod == 0 {
		a.RotationPeriod = defaults.LogRotationPeriod
	}
	if a.DirMask == nil {
		mask := os.FileMode(teleport.DirMaskSharedGroup)
		a.DirMask = &mask
	}
	if (a.GID != nil && a.UID == nil) || (a.UID != nil && a.GID == nil) {
		return trace.BadParameter("if UID or GID is set, both should be specified")
	}
	if a.PlaybackRecycleTTL == 0 {
		a.PlaybackRecycleTTL = defaults.PlaybackRecycleTTL
	}
	if a.Context == nil {
		a.Context = context.Background()
	}
	return nil
}

// NewAuditLog creates and returns a new Audit Log object which will store its log files in
// a given directory.
func NewAuditLog(cfg AuditLogConfig) (*AuditLog, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	ctx, cancel := context.WithCancel(cfg.Context)
	al := &AuditLog{
		playbackDir:    filepath.Join(cfg.DataDir, PlaybackDir, SessionLogsDir, apidefaults.Namespace),
		AuditLogConfig: cfg,
		log: log.WithFields(log.Fields{
			trace.Component: teleport.ComponentAuditLog,
		}),
		activeDownloads: make(map[string]context.Context),
		ctx:             ctx,
		cancel:          cancel,
	}
	// create a directory for audit logs, audit log does not create
	// session logs before migrations are run in case if the directory
	// has to be moved
	auditDir := filepath.Join(cfg.DataDir, cfg.ServerID)
	if err := os.MkdirAll(auditDir, *cfg.DirMask); err != nil {
		return nil, trace.ConvertSystemError(err)
	}
	// create a directory for session logs:
	sessionDir := filepath.Join(cfg.DataDir, cfg.ServerID, SessionLogsDir, apidefaults.Namespace)
	if err := os.MkdirAll(sessionDir, *cfg.DirMask); err != nil {
		return nil, trace.ConvertSystemError(err)
	}
	// create a directory for uncompressed playbacks
	if err := os.MkdirAll(filepath.Join(al.playbackDir), *cfg.DirMask); err != nil {
		return nil, trace.ConvertSystemError(err)
	}
	if cfg.UID != nil && cfg.GID != nil {
		err := os.Chown(cfg.DataDir, *cfg.UID, *cfg.GID)
		if err != nil {
			return nil, trace.ConvertSystemError(err)
		}
		err = os.Chown(sessionDir, *cfg.UID, *cfg.GID)
		if err != nil {
			return nil, trace.ConvertSystemError(err)
		}
		err = os.Chown(al.playbackDir, *cfg.UID, *cfg.GID)
		if err != nil {
			return nil, trace.ConvertSystemError(err)
		}
	}

	if al.ExternalLog == nil {
		var err error
		al.localLog, err = NewFileLog(FileLogConfig{
			RotationPeriod: al.RotationPeriod,
			Dir:            auditDir,
			SymlinkDir:     cfg.DataDir,
			Clock:          al.Clock,
			UIDGenerator:   al.UIDGenerator,
			SearchDirs:     al.auditDirs,
		})
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}

	go al.periodicSpaceMonitor()

	return al, nil
}

func getAuthServers(dataDir string) ([]string, error) {
	// scan the log directory:
	df, err := os.Open(dataDir)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer df.Close()
	entries, err := df.Readdir(-1)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var authServers []string
	for i := range entries {
		fi := entries[i]
		if fi.IsDir() {
			fileName := filepath.Base(fi.Name())
			// TODO: this is not the best solution because these names
			// can be colliding with customer-picked names, so consider
			// moving the folders to a folder level up and keep the servers
			// one small
			if fileName != PlaybackDir && fileName != teleport.ComponentUpload && fileName != RecordsDir {
				authServers = append(authServers, fileName)
			}
		}
	}
	return authServers, nil
}

// createOrGetDownload creates a new download sync entry for a given session,
// if there is no active download in progress, or returns an existing one.
// if the new context has been created, cancel function is returned as a
// second argument. Caller should call this function to signal that download has been
// completed or failed.
func (l *AuditLog) createOrGetDownload(path string) (context.Context, context.CancelFunc) {
	l.Lock()
	defer l.Unlock()
	ctx, ok := l.activeDownloads[path]
	if ok {
		return ctx, nil
	}
	ctx, cancel := context.WithCancel(context.TODO())
	l.activeDownloads[path] = ctx
	return ctx, func() {
		cancel()
		l.Lock()
		defer l.Unlock()
		delete(l.activeDownloads, path)
	}
}

// EmitAuditEvent adds a new event to the local file log
func (l *AuditLog) EmitAuditEvent(ctx context.Context, event apievents.AuditEvent) error {
	// If an external logger has been set, use it as the emitter, otherwise
	// fallback to the local disk based emitter.
	var emitAuditEvent func(ctx context.Context, event apievents.AuditEvent) error

	if l.ExternalLog != nil {
		emitAuditEvent = l.ExternalLog.EmitAuditEvent
	} else {
		emitAuditEvent = l.getLocalLog().EmitAuditEvent
	}
	err := emitAuditEvent(ctx, event)
	if err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// auditDirs returns directories used for audit log storage
func (l *AuditLog) auditDirs() ([]string, error) {
	authServers, err := getAuthServers(l.DataDir)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var out []string
	for _, serverID := range authServers {
		out = append(out, filepath.Join(l.DataDir, serverID))
	}
	return out, nil
}

func (l *AuditLog) SearchEvents(fromUTC, toUTC time.Time, namespace string, eventType []string, limit int, order types.EventOrder, startKey string) ([]apievents.AuditEvent, string, error) {
	g := l.log.WithFields(log.Fields{"namespace": namespace, "eventType": eventType, "limit": limit})
	g.Debugf("SearchEvents(%v, %v)", fromUTC, toUTC)
	if limit <= 0 {
		limit = defaults.EventsIterationLimit
	}
	if limit > defaults.EventsMaxIterationLimit {
		return nil, "", trace.BadParameter("limit %v exceeds max iteration limit %v", limit, defaults.MaxIterationLimit)
	}
	if l.ExternalLog != nil {
		return l.ExternalLog.SearchEvents(fromUTC, toUTC, namespace, eventType, limit, order, startKey)
	}
	return l.localLog.SearchEvents(fromUTC, toUTC, namespace, eventType, limit, order, startKey)
}

func (l *AuditLog) SearchSessionEvents(fromUTC, toUTC time.Time, limit int, order types.EventOrder, startKey string, cond *types.WhereExpr, sessionID string) ([]apievents.AuditEvent, string, error) {
	l.log.Debugf("SearchSessionEvents(%v, %v, %v)", fromUTC, toUTC, limit)
	if l.ExternalLog != nil {
		return l.ExternalLog.SearchSessionEvents(fromUTC, toUTC, limit, order, startKey, cond, sessionID)
	}
	return l.localLog.SearchSessionEvents(fromUTC, toUTC, limit, order, startKey, cond, sessionID)
}

// StreamSessionEvents streams all events from a given session recording. An error is returned on the first
// channel if one is encountered. Otherwise the event channel is closed when the stream ends.
// The event channel is not closed on error to prevent race conditions in downstream select statements.
func (l *AuditLog) StreamSessionEvents(ctx context.Context, sessionID session.ID, startIndex int64) (chan apievents.AuditEvent, chan error) {
	l.log.Debugf("StreamSessionEvents(%v)", sessionID)
	e := make(chan error, 1)
	c := make(chan apievents.AuditEvent)

	tarballPath := filepath.Join(l.playbackDir, string(sessionID)+".stream.tar")
	downloadCtx, cancel := l.createOrGetDownload(tarballPath)

	// Wait until another in progress download finishes and use its tarball.
	if cancel == nil {
		l.log.Debugf("Another download is in progress for %v, waiting until it gets completed.", sessionID)
		select {
		case <-downloadCtx.Done():
		case <-l.ctx.Done():
			e <- trace.BadParameter("audit log is closing, aborting the download")
			return c, e
		}
	} else {
		defer cancel()
	}

	rawSession, err := os.OpenFile(tarballPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0640)
	if err != nil {
		e <- trace.Wrap(err)
		return c, e
	}

	start := time.Now()
	if err := l.UploadHandler.Download(l.ctx, sessionID, rawSession); err != nil {
		// remove partially downloaded tarball
		if rmErr := os.Remove(tarballPath); rmErr != nil {
			l.log.WithError(rmErr).Warningf("Failed to remove file %v.", tarballPath)
		}

		e <- trace.Wrap(err)
		return c, e
	}

	l.log.WithField("duration", time.Since(start)).Debugf("Downloaded %v to %v.", sessionID, tarballPath)
	_, err = rawSession.Seek(0, 0)
	if err != nil {
		e <- trace.Wrap(err)
		return c, e
	}

	if err != nil {
		e <- trace.Wrap(err)
		return c, e
	}

	protoReader := NewProtoReader(rawSession)

	go func() {
		for {
			if ctx.Err() != nil {
				e <- trace.Wrap(ctx.Err())
				break
			}

			event, err := protoReader.Read(ctx)
			if err != nil {
				if err != io.EOF {
					e <- trace.Wrap(err)
				} else {
					close(c)
				}

				break
			}

			if event.GetIndex() >= startIndex {
				c <- event
			}
		}
	}()

	return c, e
}

// getLocalLog returns the local (file based) audit log.
func (l *AuditLog) getLocalLog() IAuditLog {
	l.RLock()
	defer l.RUnlock()

	// If no local log exists, which can occur during shutdown when the local log
	// has been set to "nil" by Close, return a nop audit log.
	if l.localLog == nil {
		return NewDiscardAuditLog()
	}
	return l.localLog
}

// Closes the audit log, which includes closing all file handles and releasing
// all session loggers
func (l *AuditLog) Close() error {
	if l.ExternalLog != nil {
		if err := l.ExternalLog.Close(); err != nil {
			log.Warningf("Close failure: %v", err)
		}
	}
	l.cancel()
	l.Lock()
	defer l.Unlock()

	if l.localLog != nil {
		if err := l.localLog.Close(); err != nil {
			log.Warningf("Close failure: %v", err)
		}
		l.localLog = nil
	}
	return nil
}

// periodicSpaceMonitor run forever monitoring how much disk space has been
// used on disk.
func (l *AuditLog) periodicSpaceMonitor() {
	ticker := time.NewTicker(defaults.DiskAlertInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Find out what percentage of disk space is used.
			usedPercent, err := utils.PercentUsed(l.DataDir)
			if err != nil {
				log.Warnf("Disk space monitoring failed: %v.", err)
				continue
			}

			// If used percentage goes above the alerting level, write to logs as well.
			if usedPercent > float64(defaults.DiskAlertThreshold) {
				log.Warnf("Free disk space for audit log is running low, %v%% of disk used.", usedPercent)
			}
		case <-l.ctx.Done():
			return
		}
	}
}
