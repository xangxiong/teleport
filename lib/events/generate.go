/*
Copyright 2020 Gravitational, Inc.

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
	"time"

	"github.com/google/uuid"
	"github.com/jonboulle/clockwork"
)

// SessionParams specifies optional parameters
// for generated session
type SessionParams struct {
	// PrintEvents sets up print events count
	PrintEvents int64
	// Clock is an optional clock setting start
	// and offset time of the event
	Clock clockwork.Clock
	// ServerID is an optional server ID
	ServerID string
	// SessionID is an optional session ID to set
	SessionID string
	// ClusterName is an optional originating cluster name
	ClusterName string
}

// SetDefaults sets parameters defaults
func (p *SessionParams) SetDefaults() {
	if p.Clock == nil {
		p.Clock = clockwork.NewFakeClockAt(
			time.Date(2020, 03, 30, 15, 58, 54, 561*int(time.Millisecond), time.UTC))
	}
	if p.ServerID == "" {
		p.ServerID = uuid.New().String()
	}
	if p.SessionID == "" {
		p.SessionID = uuid.New().String()
	}
}
