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

//go:build windows
// +build windows

package winwebauthn_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"syscall"
	"testing"
	"unsafe"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/google/uuid"
	wanlib "github.com/gravitational/teleport/lib/auth/webauthn"
	"github.com/gravitational/teleport/lib/auth/winwebauthn"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// TODO(tobiaszheller): add some flags when to run.
func TestFullFlow(t *testing.T) {
	const llamaUser = "llama"

	web, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "Teleport",
		RPID:          uuid.NewString(),
		RPOrigin:      "https://goteleport.com",
	})
	require.NoError(t, err)

	tests := []struct {
		name            string
		webUser         *fakeUser
		origin, user    string
		modifyAssertion func(a *wanlib.CredentialAssertion)
		wantUser        string
	}{
		{
			name:    "standard flow",
			webUser: &fakeUser{id: []byte(uuid.NewString()), name: llamaUser},
			origin:  web.Config.RPOrigin,
			// modifyAssertion: func(a *wanlib.CredentialAssertion) {
			// 	a.Response.AllowedCredentials = nil // aka passwordless
			// },
			wantUser: llamaUser,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			webUser := test.webUser
			origin := test.origin

			// Registration section.
			cc, sessionData, err := web.BeginRegistration(webUser)
			require.NoError(t, err)

			dialogOkCancel(t, "Please use windows hello device to register")

			ctx := context.Background()
			reg, err := winwebauthn.Register(ctx, origin, (*wanlib.CredentialCreation)(cc))
			require.NoError(t, err, "Register failed")
			// TODO(tobiaszheller): run proper assertion
			// assert.Equal(t, 1, fake.userPrompts, "unexpected number of Registation prompts")

			// We have to marshal and parse ccr due to an unavoidable quirk of the
			// webauthn API.
			body, err := json.Marshal(wanlib.CredentialCreationResponseFromProto(reg.GetWebauthn()))
			require.NoError(t, err)

			var ccr protocol.CredentialCreationResponse
			err = json.Unmarshal(body, &ccr)
			require.NoError(t, err, "Json failed")
			t.Log(ccr.AttestationResponse)
			_, err = ccr.AttestationResponse.Parse()
			if err != nil {
				var pError *protocol.Error
				if errors.As(err, &pError) {
					log.Fatalf("Failed to AttestationResponse: %v, details %s, info %s", err, pError.Details, pError.DevInfo)
				}
				t.Fatal(333, err)
			}

			parsedCCR, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(body))
			require.NoError(t, err, "ParseCredentialCreationResponseBody failed")

			cred, err := web.CreateCredential(webUser, *sessionData, parsedCCR)
			require.NoError(t, err, "CreateCredential failed")
			// Save credential for Login test below.
			webUser.credentials = append(webUser.credentials, *cred)

			// Login section.
			a, sessionData, err := web.BeginLogin(webUser)
			require.NoError(t, err, "BeginLogin failed")
			assertion := (*wanlib.CredentialAssertion)(a)
			// test.modifyAssertion(assertion)

			assertionResp, _, err := winwebauthn.Login(ctx, origin, assertion, nil)
			require.NoError(t, err, "Login failed")
			// TODO(tobiaszheller): proper assertings
			// assert.Equal(t, test.wantUser, actualUser, "actualUser mismatch")
			// assert.Equal(t, 2, fake.userPrompts, "unexpected number of Login prompts")

			// Same as above: easiest way to validate the assertion is to marshal
			// and then parse the body.
			body, err = json.Marshal(wanlib.CredentialAssertionResponseFromProto(assertionResp.GetWebauthn()))
			require.NoError(t, err)
			parsedAssertion, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(body))
			require.NoError(t, err, "ParseCredentialRequestResponseBody failed")

			_, err = web.ValidateLogin(webUser, *sessionData, parsedAssertion)
			require.NoError(t, err, "ValidatLogin failed")
		})
	}
}

type fakeUser struct {
	id          []byte
	name        string
	credentials []webauthn.Credential
}

func (u *fakeUser) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}

func (u *fakeUser) WebAuthnDisplayName() string {
	return u.name
}

func (u *fakeUser) WebAuthnID() []byte {
	return u.id
}

func (u *fakeUser) WebAuthnIcon() string {
	return ""
}

func (u *fakeUser) WebAuthnName() string {
	return u.name
}

var (
	moduser32               = windows.NewLazySystemDLL("user32.dll")
	procGetForegroundWindow = moduser32.NewProc("GetForegroundWindow")
	procMessageBoxW         = moduser32.NewProc("MessageBoxW")
)

func messageBox(hwnd syscall.Handle, caption, title string, flags uint) int {
	ret, _, _ := procMessageBoxW.Call(
		uintptr(hwnd),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(caption))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(title))),
		uintptr(flags))

	return int(ret)
}

func dialogOk(caption string) bool {
	const MB_OK = 0x00000000
	hwnd, err := getForegroundWindow()
	if err != nil {
		panic(err)
	}
	// return value 1 indicates OK was selected
	return messageBox(hwnd, caption, "Teleport winwebauthn tests", MB_OK) == 1
}

func dialogOkCancel(t *testing.T, caption string) {
	const MB_OKCANCEL = 0x00000001
	hwnd, err := getForegroundWindow()
	if err != nil {
		panic(err)
	}
	v := messageBox(hwnd, caption, "Teleport winwebauthn tests", MB_OKCANCEL)
	if v == 2 {
		t.Fatal("Operation was canceled by used")
	}
	if v != 1 {
		t.Fatal("Unexpected value from dialog: ", v)
	}
}

func getForegroundWindow() (hwnd syscall.Handle, err error) {
	r0, _, err := procGetForegroundWindow.Call()
	if err != syscall.Errno(0) {
		return syscall.InvalidHandle, err
	}
	return syscall.Handle(r0), nil
}
