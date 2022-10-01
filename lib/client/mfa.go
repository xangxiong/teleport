/*
Copyright 2021 Gravitational, Inc.

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

package client

import (
	wanlib "github.com/gravitational/teleport/lib/auth/webauthn"
)

// MFAAuthenticateChallenge is an MFA authentication challenge sent on user
// login / authentication ceremonies.
type MFAAuthenticateChallenge struct {
	// WebauthnChallenge contains a WebAuthn credential assertion used for
	// login/authentication ceremonies.
	WebauthnChallenge *wanlib.CredentialAssertion `json:"webauthn_challenge"`
	// TOTPChallenge specifies whether TOTP is supported for this user.
	TOTPChallenge bool `json:"totp_challenge"`
}
