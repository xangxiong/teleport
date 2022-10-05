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
	"fmt"
	"io"
	"math"
	"time"

	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/lib/session"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
)

const (
	// EventType is event type/kind
	EventType = "event"
	// EventID is a unique event identifier
	EventID = "uid"
	// EventCode is a code that uniquely identifies a particular event type
	EventCode = "code"
	// EventTime is event time
	EventTime = "time"
	// EventLogin is OS login
	EventLogin = "login"
	// EventUser is teleport user name
	EventUser = "user"
	// EventProtocol specifies protocol that was captured
	EventProtocol = "proto"
	// EventProtocolsSSH specifies SSH as a type of captured protocol
	EventProtocolSSH = "ssh"
	// LocalAddr is a target address on the host
	LocalAddr = "addr.local"
	// RemoteAddr is a client (user's) address
	RemoteAddr = "addr.remote"
	// EventCursor is an event ID (used as cursor value for enumeration, not stored)
	EventCursor = "id"

	// EventIndex is an event index as received from the logging server
	EventIndex = "ei"

	// EventNamespace is a namespace of the session event
	EventNamespace = "namespace"

	// SessionPrintEvent event happens every time a write occurs to
	// temirnal I/O during a session
	SessionPrintEvent = "print"

	// SessionPrintEventBytes says how many bytes have been written into the session
	// during "print" event
	SessionPrintEventBytes = "bytes"

	// SessionEventTimestamp is an offset (in milliseconds) since the beginning of the
	// session when the terminal IO event happened
	SessionEventTimestamp = "ms"

	// SessionEvent indicates that session has been initiated
	// or updated by a joining party on the server
	SessionStartEvent = "session.start"

	// SessionEndEvent indicates that a session has ended
	SessionEndEvent = "session.end"

	// SessionUploadEvent indicates that session has been uploaded to the external storage
	SessionUploadEvent = "session.upload"

	// URL is used for a session upload URL
	URL = "url"

	// SessionEventID is a unique UUID of the session.
	SessionEventID = "sid"

	// SessionServerID is the UUID of the server the session occurred on.
	SessionServerID = "server_id"

	// SessionServerHostname is the hostname of the server the session occurred on.
	SessionServerHostname = "server_hostname"

	// SessionServerAddr is the address of the server the session occurred on.
	SessionServerAddr = "server_addr"

	// SessionStartTime is the timestamp at which the session began.
	SessionStartTime = "session_start"

	// SessionRecordingType is the type of session recording.
	// Possible values are node (default), proxy, node-sync, proxy-sync, or off.
	SessionRecordingType = "session_recording"

	// SessionEndTime is the timestamp at which the session ended.
	SessionEndTime = "session_stop"

	// SessionEnhancedRecording is used to indicate if the recording was an
	// enhanced recording or not.
	SessionEnhancedRecording = "enhanced_recording"

	// SessionInteractive is used to indicate if the session was interactive
	// (has PTY attached) or not (exec session).
	SessionInteractive = "interactive"

	// SessionParticipants is a list of participants in the session.
	SessionParticipants = "participants"

	// SessionServerLabels are the labels (static and dynamic) of the server the
	// session occurred on.
	SessionServerLabels = "server_labels"

	// SessionClusterName is the cluster name that the session occurred in
	SessionClusterName = "cluster_name"

	// SessionByteOffset is the number of bytes written to session stream since
	// the beginning
	SessionByteOffset = "offset"

	// SessionJoinEvent indicates that someone joined a session
	SessionJoinEvent = "session.join"
	// SessionLeaveEvent indicates that someone left a session
	SessionLeaveEvent = "session.leave"

	// Data transfer events.
	SessionDataEvent = "session.data"
	DataTransmitted  = "tx"
	DataReceived     = "rx"

	// ClientDisconnectEvent is emitted when client is disconnected
	// by the server due to inactivity or any other reason
	ClientDisconnectEvent = "client.disconnect"

	// Reason is a field that specifies reason for event, e.g. in disconnect
	// event it explains why server disconnected the client
	Reason = "reason"

	// IdentityAttributes is a map of user attributes
	// received from identity provider
	IdentityAttributes = "attributes"

	// AccessRequestCreateEvent is emitted when a new access request is created.
	AccessRequestCreateEvent = "access_request.create"
	// AccessRequestUpdateEvent is emitted when a request's state is updated.
	AccessRequestUpdateEvent = "access_request.update"
	// AccessRequestReviewEvent is emitted when a review is applied to a request.
	AccessRequestReviewEvent = "access_request.review"
	// AccessRequestDeleteEvent is emitted when a new access request is deleted.
	AccessRequestDeleteEvent = "access_request.delete"
	// AccessRequestResourceSearch is emitted when a user searches for
	// resources as part of a search-based access request.
	AccessRequestResourceSearch = "access_request.search"
	// AccessRequestDelegator is used by teleport plugins to indicate the identity
	// which caused them to update state.
	AccessRequestDelegator = "delegator"
	// AccessRequestState is the state of a request.
	AccessRequestState = "state"
	// AccessRequestID is the ID of an access request.
	AccessRequestID = "id"

	// UpdatedBy indicates the user who modified some resource:
	//  - updating a request state
	//  - updating a user record
	UpdatedBy = "updated_by"

	// FieldName contains name, e.g. resource name, etc.
	FieldName = "name"

	// ExecEvent is an exec command executed by script or user on
	// the server side
	ExecEvent        = "exec"
	ExecEventCommand = "command"
	ExecEventCode    = "exitCode"
	ExecEventError   = "exitError"

	// SubsystemEvent is the result of the execution of a subsystem.
	SubsystemEvent = "subsystem"
	SubsystemName  = "name"
	SubsystemError = "exitError"

	// X11 forwarding event
	X11ForwardEvent   = "x11-forward"
	X11ForwardSuccess = "success"
	X11ForwardErr     = "error"

	// Port forwarding event
	PortForwardEvent   = "port"
	PortForwardAddr    = "addr"
	PortForwardSuccess = "success"
	PortForwardErr     = "error"

	// AuthAttemptEvent is authentication attempt that either
	// succeeded or failed based on event status
	AuthAttemptEvent = "auth"

	// SCPEvent means data transfer that occurred on the server
	SCPEvent          = "scp"
	SCPPath           = "path"
	SCPLengh          = "len"
	SCPAction         = "action"
	SCPActionUpload   = "upload"
	SCPActionDownload = "download"

	// SFTPEvent means a user attempted a file operation
	SFTPEvent = "sftp"
	SFTPPath  = "path"

	// ResizeEvent means that some user resized PTY on the client
	ResizeEvent  = "resize"
	TerminalSize = "size" // expressed as 'W:H'

	// SessionUploadIndex is a very large number of the event index
	// to indicate that this is the last event in the chain
	// used for the last event of the sesion - session upload
	SessionUploadIndex = math.MaxInt32
	// SessionDataIndex is a very large number of the event index
	// to indicate one of the last session events, used to report
	// data transfer
	SessionDataIndex = math.MaxInt32 - 1

	// SessionCommandEvent is emitted when an executable is run within a session.
	SessionCommandEvent = "session.command"

	// SessionDiskEvent is emitted when a file is opened within an session.
	SessionDiskEvent = "session.disk"

	// SessionNetworkEvent is emitted when a network connection is initiated with a
	// session.
	SessionNetworkEvent = "session.network"

	// PID is the ID of the process.
	PID = "pid"

	// PPID is the PID of the parent process.
	PPID = "ppid"

	// CgroupID is the internal cgroupv2 ID of the event.
	CgroupID = "cgroup_id"

	// Program is name of the executable.
	Program = "program"

	// Path is the full path to the executable.
	Path = "path"

	// Argv is the list of arguments to the program. Note, the first element does
	// not contain the name of the process.
	Argv = "argv"

	// ReturnCode is the return code of execve.
	ReturnCode = "return_code"

	// Flags are the flags passed to open.
	Flags = "flags"

	// SrcAddr is the source IP address of the connection.
	SrcAddr = "src_addr"

	// DstAddr is the destination IP address of the connection.
	DstAddr = "dst_addr"

	// DstPort is the destination port of the connection.
	DstPort = "dst_port"

	// TCPVersion is the version of TCP (4 or 6).
	TCPVersion = "version"

	// RoleCreatedEvent fires when role is created/updated.
	RoleCreatedEvent = "role.created"
	// RoleDeletedEvent fires when role is deleted.
	RoleDeletedEvent = "role.deleted"

	// TrustedClusterCreateEvent is the event for creating a trusted cluster.
	TrustedClusterCreateEvent = "trusted_cluster.create"
	// TrustedClusterDeleteEvent is the event for removing a trusted cluster.
	TrustedClusterDeleteEvent = "trusted_cluster.delete"
	// TrustedClusterTokenCreateEvent is the event for
	// creating new join token for a trusted cluster.
	TrustedClusterTokenCreateEvent = "trusted_cluster_token.create"

	// SessionRejected fires when a user's attempt to create an authenticated
	// session has been rejected due to exceeding a session control limit.
	SessionRejectedEvent = "session.rejected"

	// SessionConnect is emitted when any ssh connection is made
	SessionConnectEvent = "session.connect"

	// SessionRejectedReasonMaxConnections indicates that a session.rejected event
	// corresponds to enforcement of the max_connections control.
	SessionRejectedReasonMaxConnections = "max_connections limit reached"
	// SessionRejectedReasonMaxSessions indicates that a session.rejected event
	// corresponds to enforcement of the max_sessions control.
	SessionRejectedReasonMaxSessions = "max_sessions limit reached"

	// Maximum is an event field specifying a maximal value (e.g. the value
	// of `max_connections` for a `session.rejected` event).
	Maximum = "max"

	// LockCreatedEvent fires when a lock is created/updated.
	LockCreatedEvent = "lock.created"
	// LockDeletedEvent fires when a lock is deleted.
	LockDeletedEvent = "lock.deleted"

	// CertificateCreateEvent is emitted when a certificate is issued.
	CertificateCreateEvent = "cert.create"

	// RenewableCertificateGenerationMismatchEvent is emitted when a renewable
	// certificate's generation counter is invalid.
	RenewableCertificateGenerationMismatchEvent = "cert.generation_mismatch"

	// CertificateTypeUser is the CertificateType for certificate events pertaining to user certificates.
	CertificateTypeUser = "user"

	// UpgradeWindowStartUpdateEvent is emitted when the upgrade window start time
	// is updated. Used only for teleport cloud.
	UpgradeWindowStartUpdateEvent = "upgradewindowstart.update"

	// SessionRecordingAccessEvent is emitted when a session recording is accessed
	SessionRecordingAccessEvent = "session.recording.access"

	// UnknownEvent is any event received that isn't recognized as any other event type.
	UnknownEvent = apievents.UnknownEvent
)

const (
	// MaxChunkBytes defines the maximum size of a session stream chunk that
	// can be requested via AuditLog.GetSessionChunk(). Set to 5MB
	MaxChunkBytes = 1024 * 1024 * 5
)

const (
	// V1 is the V1 version of slice chunks API,
	// it is 0 because it was not defined before
	V1 = 0
	// V2 is the V2 version of slice chunks  API
	V2 = 2
	// V3 is almost like V2, but it assumes
	// that session recordings are being uploaded
	// at the end of the session, so it skips writing session event index
	// on the fly
	V3 = 3
)

// ServerMetadataGetter represents interface
// that provides information about its server id
type ServerMetadataGetter interface {
	// GetServerID returns event server ID
	GetServerID() string

	// GetServerNamespace returns event server namespace
	GetServerNamespace() string

	// GetClusterName returns the originating teleport cluster name
	GetClusterName() string

	// GetForwardedBy returns the ID of the server that forwarded this event.
	GetForwardedBy() string
}

// ServerMetadataSetter represents interface
// that provides information about its server id
type ServerMetadataSetter interface {
	// SetServerID sets server ID of the event
	SetServerID(string)

	// SetServerNamespace returns event server namespace
	SetServerNamespace(string)
}

// SessionMetadataGetter represents interface
// that provides information about events' session metadata
type SessionMetadataGetter interface {
	// GetSessionID returns event session ID
	GetSessionID() string
}

// SessionMetadataSetter represents interface
// that sets session metadata
type SessionMetadataSetter interface {
	// SetSessionID sets event session ID
	SetSessionID(string)
}

// StreamPart represents uploaded stream part
type StreamPart struct {
	// Number is a part number
	Number int64
	// ETag is a part e-tag
	ETag string
}

// StreamUpload represents stream multipart upload
type StreamUpload struct {
	// ID is unique upload ID
	ID string
	// SessionID is a session ID of the upload
	SessionID session.ID
	// Initiated contains the timestamp of when the upload
	// was initiated, not always initialized
	Initiated time.Time
}

// String returns user friendly representation of the upload
func (u StreamUpload) String() string {
	return fmt.Sprintf("Upload(session=%v, id=%v, initiated=%v)", u.SessionID, u.ID, u.Initiated)
}

// CheckAndSetDefaults checks and sets default values
func (u *StreamUpload) CheckAndSetDefaults() error {
	if u.ID == "" {
		return trace.BadParameter("missing parameter ID")
	}
	if u.SessionID == "" {
		return trace.BadParameter("missing parameter SessionID")
	}
	return nil
}

// MultipartUploader handles multipart uploads and downloads for session streams
type MultipartUploader interface {
	// CreateUpload creates a multipart upload
	CreateUpload(ctx context.Context, sessionID session.ID) (*StreamUpload, error)
	// CompleteUpload completes the upload
	CompleteUpload(ctx context.Context, upload StreamUpload, parts []StreamPart) error
	// ReserveUploadPart reserves an upload part. Reserve is used to identify
	// upload errors beforehand.
	ReserveUploadPart(ctx context.Context, upload StreamUpload, partNumber int64) error
	// UploadPart uploads part and returns the part
	UploadPart(ctx context.Context, upload StreamUpload, partNumber int64, partBody io.ReadSeeker) (*StreamPart, error)
	// ListParts returns all uploaded parts for the completed upload in sorted order
	ListParts(ctx context.Context, upload StreamUpload) ([]StreamPart, error)
	// ListUploads lists uploads that have been initiated but not completed with
	// earlier uploads returned first
	ListUploads(ctx context.Context) ([]StreamUpload, error)
	// GetUploadMetadata gets the upload metadata
	GetUploadMetadata(sessionID session.ID) UploadMetadata
}

// UploadMetadata contains data about the session upload
type UploadMetadata struct {
	// URL is the url at which the session recording is located
	// it is free-form and uploader-specific
	URL string
	// SessionID is the event session ID
	SessionID session.ID
}

// UploadMetadataGetter gets the metadata for session upload
type UploadMetadataGetter interface {
	GetUploadMetadata(sid session.ID) UploadMetadata
}

// StreamWriter implements io.Writer to be plugged into the multi-writer
// associated with every session. It forwards session stream to the audit log
type StreamWriter interface {
	io.Writer
	apievents.Stream
}

// IAuditLog is the primary (and the only external-facing) interface for AuditLogger.
// If you wish to implement a different kind of logger (not filesystem-based), you
// have to implement this interface
type IAuditLog interface {
	// Closer releases connection and resources associated with log if any
	io.Closer
}

// EventFields instance is attached to every logged event
type EventFields utils.Fields

// String returns a string representation of an event structure
func (f EventFields) AsString() string {
	return fmt.Sprintf("%s: login=%s, id=%v, bytes=%v",
		f.GetString(EventType),
		f.GetString(EventLogin),
		f.GetInt(EventCursor),
		f.GetInt(SessionPrintEventBytes))

}

// GetType returns the type (string) of the event
func (f EventFields) GetType() string {
	return f.GetString(EventType)
}

// GetID returns the unique event ID
func (f EventFields) GetID() string {
	return f.GetString(EventID)
}

// GetCode returns the event code
func (f EventFields) GetCode() string {
	return f.GetString(EventCode)
}

// GetTimestamp returns the event timestamp (when it was emitted)
func (f EventFields) GetTimestamp() time.Time {
	return f.GetTime(EventTime)
}

// GetString returns a string representation of a logged field
func (f EventFields) GetString(key string) string {
	return utils.Fields(f).GetString(key)
}

// GetString returns a slice-of-strings representation of a logged field.
func (f EventFields) GetStrings(key string) []string {
	return utils.Fields(f).GetStrings(key)
}

// GetInt returns an int representation of a logged field
func (f EventFields) GetInt(key string) int {
	return utils.Fields(f).GetInt(key)
}

// GetTime returns a time.Time representation of a logged field
func (f EventFields) GetTime(key string) time.Time {
	return utils.Fields(f).GetTime(key)
}

// HasField returns true if the field exists in the event.
func (f EventFields) HasField(key string) bool {
	return utils.Fields(f).HasField(key)
}
