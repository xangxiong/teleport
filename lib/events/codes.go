/*
Copyright 2019 Gravitational, Inc.

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

import apievents "github.com/gravitational/teleport/api/types/events"

// Event describes an audit log event.
type Event struct {
	// Name is the event name.
	Name string
	// Code is the unique event code.
	Code string
}

// There is no strict algorithm for picking an event code, however existing
// event codes are currently loosely categorized as follows:
//
//   - Teleport event codes start with "T" and belong in this const block.
//
//   - Related events are grouped starting with the same number.
//     eg: All user related events are grouped under 1xxx.
//
//   - Suffix code with one of these letters: I (info), W (warn), E (error).
const (
	// SessionRejectedCode is an event code for when a user's attempt to create an
	// session/connection has been rejected.
	SessionRejectedCode = "T1006W"

	// SessionStartCode is the session start event code.
	SessionStartCode = "T2000I"
	// SessionJoinCode is the session join event code.
	SessionJoinCode = "T2001I"
	// TerminalResizeCode is the terminal resize event code.
	TerminalResizeCode = "T2002I"
	// SessionLeaveCode is the session leave event code.
	SessionLeaveCode = "T2003I"
	// SessionEndCode is the session end event code.
	SessionEndCode = "T2004I"
	// SessionUploadCode is the session upload event code.
	SessionUploadCode = "T2005I"
	// SessionDataCode is the session data event code.
	SessionDataCode = "T2006I"
	// SessionConnectCode is the session connect event code.
	SessionConnectCode = "T2010I"
	// SessionRecordingAccessCode is the session recording view data event code.
	SessionRecordingAccessCode = "T2012I"

	// SubsystemCode is the subsystem event code.
	SubsystemCode = "T3001I"
	// SubsystemFailureCode is the subsystem failure event code.
	SubsystemFailureCode = "T3001E"
	// ExecCode is the exec event code.
	ExecCode = "T3002I"
	// ExecFailureCode is the exec failure event code.
	ExecFailureCode = "T3002E"
	// PortForwardCode is the port forward event code.
	PortForwardCode = "T3003I"
	// PortForwardFailureCode is the port forward failure event code.
	PortForwardFailureCode = "T3003E"
	// SCPDownloadCode is the file download event code.
	SCPDownloadCode = "T3004I"
	// SCPDownloadFailureCode is the file download event failure code.
	SCPDownloadFailureCode = "T3004E"
	// SCPUploadCode is the file upload event code.
	SCPUploadCode = "T3005I"
	// SCPUploadFailureCode is the file upload failure event code.
	SCPUploadFailureCode = "T3005E"
	// ClientDisconnectCode is the client disconnect event code.
	ClientDisconnectCode = "T3006I"
	// AuthAttemptFailureCode is the auth attempt failure event code.
	AuthAttemptFailureCode = "T3007W"
	// X11ForwardCode is the x11 forward event code.
	X11ForwardCode = "T3008I"
	// X11ForwardFailureCode is the x11 forward failure event code.
	X11ForwardFailureCode = "T3008W"

	// The following codes correspond to SFTP file operations.
	SFTPOpenCode            = "TS001I"
	SFTPOpenFailureCode     = "TS001E"
	SFTPCloseCode           = "TS002I"
	SFTPCloseFailureCode    = "TS002E"
	SFTPReadCode            = "TS003I"
	SFTPReadFailureCode     = "TS003E"
	SFTPWriteCode           = "TS004I"
	SFTPWriteFailureCode    = "TS004E"
	SFTPLstatCode           = "TS005I"
	SFTPLstatFailureCode    = "TS005E"
	SFTPFstatCode           = "TS006I"
	SFTPFstatFailureCode    = "TS006E"
	SFTPSetstatCode         = "TS007I"
	SFTPSetstatFailureCode  = "TS007E"
	SFTPFsetstatCode        = "TS008I"
	SFTPFsetstatFailureCode = "TS008E"
	SFTPOpendirCode         = "TS009I"
	SFTPOpendirFailureCode  = "TS009E"
	SFTPReaddirCode         = "TS010I"
	SFTPReaddirFailureCode  = "TS010E"
	SFTPRemoveCode          = "TS011I"
	SFTPRemoveFailureCode   = "TS011E"
	SFTPMkdirCode           = "TS012I"
	SFTPMkdirFailureCode    = "TS012E"
	SFTPRmdirCode           = "TS013I"
	SFTPRmdirFailureCode    = "TS013E"
	SFTPRealpathCode        = "TS014I"
	SFTPRealpathFailureCode = "TS014E"
	SFTPStatCode            = "TS015I"
	SFTPStatFailureCode     = "TS015E"
	SFTPRenameCode          = "TS016I"
	SFTPRenameFailureCode   = "TS016E"
	SFTPReadlinkCode        = "TS017I"
	SFTPReadlinkFailureCode = "TS017E"
	SFTPSymlinkCode         = "TS018I"
	SFTPSymlinkFailureCode  = "TS018E"

	// SessionCommandCode is a session command code.
	SessionCommandCode = "T4000I"
	// SessionDiskCode is a session disk code.
	SessionDiskCode = "T4001I"
	// SessionNetworkCode is a session network code.
	SessionNetworkCode = "T4002I"

	// AccessRequestCreateCode is the the access request creation code.
	AccessRequestCreateCode = "T5000I"
	// AccessRequestUpdateCode is the access request state update code.
	AccessRequestUpdateCode = "T5001I"
	// AccessRequestReviewCode is the access review application code.
	AccessRequestReviewCode = "T5002I"
	// AccessRequestDeleteCode is the access request deleted code.
	AccessRequestDeleteCode = "T5003I"
	// AccessRequestResourceSearchCode is the access request resource search code.
	AccessRequestResourceSearchCode = "T5004I"

	// ResetPasswordTokenCreateCode is the token create event code.
	ResetPasswordTokenCreateCode = "T6000I"
	// RecoveryTokenCreateCode is the recovery token create event code.
	RecoveryTokenCreateCode = "T6001I"

	// TrustedClusterCreateCode is the event code for creating a trusted cluster.
	TrustedClusterCreateCode = "T7000I"
	// TrustedClusterDeleteCode is the event code for removing a trusted cluster.
	TrustedClusterDeleteCode = "T7001I"
	// TrustedClusterTokenCreateCode is the event code for
	// creating new join token for a trusted cluster.
	TrustedClusterTokenCreateCode = "T7002I"

	// LockCreatedCode is the lock created event code.
	LockCreatedCode = "TLK00I"
	// LockDeletedCode is the lock deleted event code.
	LockDeletedCode = "TLK01I"

	// CertificateCreateCode is the certificate issuance event code.
	CertificateCreateCode = "TC000I"

	// RenewableCertificateGenerationMismatchCode is the renewable cert
	// generation mismatch code.
	RenewableCertificateGenerationMismatchCode = "TCB00W"

	// UnknownCode is used when an event of unknown type is encountered.
	UnknownCode = apievents.UnknownCode
)
