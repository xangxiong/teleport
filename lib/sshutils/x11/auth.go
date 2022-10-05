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

package x11

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/gravitational/trace"
)

const (
	// mitMagicCookieProto is the default xauth protocol used for X11 forwarding.
	mitMagicCookieProto = "MIT-MAGIC-COOKIE-1"
	// mitMagicCookieSize is the number of bytes in an mit magic cookie.
	mitMagicCookieSize = 16
)

// XAuthEntry is an entry in an XAuthority database which can be used to authenticate
// and authorize requests from an XServer to the associated X display.
type XAuthEntry struct {
	// Display is an X display in the format - [hostname]:[display_number].[screen_number]
	Display Display `json:"display"`
	// Proto is an XAuthority protocol, generally "MIT-MAGIC-COOKIE-1"
	Proto string `json:"proto"`
	// Cookie is a hex encoded XAuthority cookie
	Cookie string `json:"cookie"`
}

// NewFakeXAuthEntry creates a fake xauth entry with a randomly generated MIT-MAGIC-COOKIE-1.
func NewFakeXAuthEntry(display Display) (*XAuthEntry, error) {
	cookie, err := newCookie(mitMagicCookieSize)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &XAuthEntry{
		Display: display,
		Proto:   mitMagicCookieProto,
		Cookie:  cookie,
	}, nil
}

// SpoofXAuthEntry creates a new xauth entry with a random cookie with the
// same length as the original entry's cookie. This is used to create a
// believable spoof of the client's xauth data to send to the server.
func (e *XAuthEntry) SpoofXAuthEntry() (*XAuthEntry, error) {
	spoofedCookie, err := newCookie(hex.DecodedLen(len(e.Cookie)))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &XAuthEntry{
		Display: e.Display,
		Proto:   e.Proto,
		Cookie:  spoofedCookie,
	}, nil
}

// newCookie makes a random hex-encoded cookie with the given byte length.
func newCookie(byteLength int) (string, error) {
	cookieBytes := make([]byte, byteLength)
	if _, err := rand.Read(cookieBytes); err != nil {
		return "", trace.Wrap(err)
	}
	return hex.EncodeToString(cookieBytes), nil
}

// XAuthCommand is a os/exec.Cmd wrapper for running xauth commands.
type XAuthCommand struct {
	*exec.Cmd
}

// NewXAuthCommand reate a new "xauth" command. xauthFile can be
// optionally provided to run the xauth command against a specific xauth file.
func NewXAuthCommand(ctx context.Context, xauthFile string) *XAuthCommand {
	var args []string
	if xauthFile != "" {
		args = []string{"-f", xauthFile}
	}
	return &XAuthCommand{exec.CommandContext(ctx, "xauth", args...)}
}

// ReadEntry runs "xauth list" to read the first xauth entry for the given display.
func (x *XAuthCommand) ReadEntry(display Display) (*XAuthEntry, error) {
	x.Cmd.Args = append(x.Cmd.Args, "list", display.String())
	out, err := x.output()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if len(out) == 0 {
		return nil, trace.NotFound("no xauth entry found")
	}

	// Ignore entries beyond the first listed.
	entry := strings.Split(string(out), "\n")[0]

	splitEntry := strings.Split(entry, "  ")
	if len(splitEntry) != 3 {
		return nil, trace.Errorf("invalid xAuthEntry, expected entry to have three parts")
	}
	proto, cookie := splitEntry[1], splitEntry[2]

	return &XAuthEntry{
		Display: display,
		Proto:   proto,
		Cookie:  cookie,
	}, nil
}

// RemoveEntries runs "xauth remove" to remove any xauth entries for the given display.
func (x *XAuthCommand) RemoveEntries(display Display) error {
	x.Cmd.Args = append(x.Cmd.Args, "remove", display.String())
	return trace.Wrap(x.run())
}

// AddEntry runs "xauth add" to add the given xauth entry.
func (x *XAuthCommand) AddEntry(entry XAuthEntry) error {
	x.Cmd.Args = append(x.Cmd.Args, "add", entry.Display.String(), entry.Proto, entry.Cookie)
	return trace.Wrap(x.run())
}

// GenerateUntrustedCookie runs "xauth generate untrusted" to create a new xauth entry with
// an untrusted MIT-MAGIC-COOKIE-1. A timeout can optionally be set for the xauth entry, after
// which the XServer will ignore this cookie.
func (x *XAuthCommand) GenerateUntrustedCookie(display Display, timeout time.Duration) error {
	x.Cmd.Args = append(x.Cmd.Args, "generate", display.String(), mitMagicCookieProto, "untrusted")
	x.Cmd.Args = append(x.Cmd.Args, "timeout", fmt.Sprint(timeout/time.Second))
	return trace.Wrap(x.run())
}

// run the command and return stderr if there is an error.
func (x *XAuthCommand) run() error {
	_, err := x.output()
	return trace.Wrap(err)
}

// run the command and return stdout or stderr if there is an error.
func (x *XAuthCommand) output() ([]byte, error) {
	stdout, err := x.Cmd.StdoutPipe()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	stderr, err := x.Cmd.StderrPipe()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := x.Cmd.Start(); err != nil {
		return nil, trace.Wrap(err)
	}

	// We add a conservative peak length of 10 KB to prevent potential
	// output spam from the client provided `xauth` binary
	var peakLength int64 = 10000
	out, err := io.ReadAll(io.LimitReader(stdout, peakLength))
	if err != nil {
		return nil, trace.Wrap(err)
	}

	errOut, err := io.ReadAll(io.LimitReader(stderr, peakLength))
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if err := x.Wait(); err != nil {
		return nil, trace.Wrap(err, "command \"%s\" failed with stderr: \"%s\"", strings.Join(x.Cmd.Args, " "), errOut)
	}

	return out, nil
}

// CheckXAuthPath checks if xauth is runnable in the current environment.
func CheckXAuthPath() error {
	_, err := exec.LookPath("xauth")
	return trace.Wrap(err)
}
