// Copyright 2022 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package webauthncli

// AuthenticatorAttachment allows callers to choose a specific attachment.
type AuthenticatorAttachment int

const (
	AttachmentAuto AuthenticatorAttachment = iota
	AttachmentCrossPlatform
	AttachmentPlatform
)

// CredentialInfo holds information about a WebAuthn credential, typically a
// resident public key credential.
type CredentialInfo struct {
	ID   []byte
	User UserInfo
}

// UserInfo holds information about a credential owner.
type UserInfo struct {
	// UserHandle is the WebAuthn user handle (also referred as user ID).
	UserHandle []byte
	Name       string
}

// LoginPrompt is the user interface for FIDO2Login.
//
// Prompts can have remote implementations, thus all methods may error.
type LoginPrompt interface {
	// PromptPIN prompts the user for their PIN.
	PromptPIN() (string, error)
	// PromptTouch prompts the user for a security key touch.
	// In certain situations multiple touches may be required (PIN-protected
	// devices, passwordless flows, etc).
	PromptTouch() error
	// PromptCredential prompts the user to choose a credential, in case multiple
	// credentials are available.
	// Callers are free to modify the slice, such as by sorting the credentials,
	// but must return one of the pointers contained within.
	PromptCredential(creds []*CredentialInfo) (*CredentialInfo, error)
}

// LoginOpts groups non-mandatory options for Login.
type LoginOpts struct {
	// User is the desired credential username for login.
	// If empty, Login may either choose a credential or prompt the user for input
	// (via LoginPrompt).
	User string
	// AuthenticatorAttachment specifies the desired authenticator attachment.
	AuthenticatorAttachment AuthenticatorAttachment
}

// RegisterPrompt is the user interface for FIDO2Register.
//
// Prompts can have remote implementations, thus all methods may error.
type RegisterPrompt interface {
	// PromptPIN prompts the user for their PIN.
	PromptPIN() (string, error)
	// PromptTouch prompts the user for a security key touch.
	// In certain situations multiple touches may be required (eg, PIN-protected
	// devices)
	PromptTouch() error
}
