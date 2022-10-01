/*
Copyright 2015 Gravitational, Inc.

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

package local

import (
	"time"
)

// GlobalSessionDataMaxEntries represents the maximum number of in-flight
// global WebAuthn challenges for a given scope.
// Attempting to write more instances than the max limit causes an error.
// The limit is enforced separately by Auth Server instances.
var GlobalSessionDataMaxEntries = 5000 // arbitrary

const (
	usersPrefix               = "users"
	sessionsPrefix            = "sessions"
	attemptsPrefix            = "attempts"
	pwdPrefix                 = "pwd"
	hotpPrefix                = "hotp"
	connectorsPrefix          = "connectors"
	oidcPrefix                = "oidc"
	requestsPrefix            = "requests"
	requestsTracePrefix       = "requestsTrace"
	usedTOTPPrefix            = "used_totp"
	usedTOTPTTL               = 30 * time.Second
	mfaDevicePrefix           = "mfa"
	webauthnPrefix            = "webauthn"
	webauthnGlobalSessionData = "sessionData"
	webauthnLocalAuthPrefix   = "webauthnlocalauth"
	webauthnSessionData       = "webauthnsessiondata"
	recoveryCodesPrefix       = "recoverycodes"
	recoveryAttemptsPrefix    = "recoveryattempts"
)
