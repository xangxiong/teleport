// Copyright 2021 Gravitational, Inc
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

package service

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProcessStateGetState(t *testing.T) {
	t.Parallel()

	tests := []struct {
		desc       string
		states     map[string]*componentState
		components []string
		want       componentStateEnum
	}{
		{
			desc:       "no components",
			states:     map[string]*componentState{},
			components: []string{"one"},
			want:       stateStarting,
		},
		{
			desc: "one component in stateOK",
			states: map[string]*componentState{
				"one": {state: stateOK},
			},
			components: []string{"one"},
			want:       stateOK,
		},
		{
			desc: "multiple components in stateOK",
			states: map[string]*componentState{
				"one":   {state: stateOK},
				"two":   {state: stateOK},
				"three": {state: stateOK},
			},
			components: []string{"one", "two", "three"},
			want:       stateOK,
		},
		{
			desc: "multiple components, one is degraded",
			states: map[string]*componentState{
				"one":   {state: stateRecovering},
				"two":   {state: stateDegraded},
				"three": {state: stateOK},
			},
			components: []string{"one", "two", "three"},
			want:       stateDegraded,
		},
		{
			desc: "multiple components, one is recovering",
			states: map[string]*componentState{
				"one":   {state: stateOK},
				"two":   {state: stateRecovering},
				"three": {state: stateOK},
			},
			components: []string{"one", "two", "three"},
			want:       stateRecovering,
		},
		{
			desc: "multiple components, one is starting",
			states: map[string]*componentState{
				"one":   {state: stateOK},
				"two":   {state: stateStarting},
				"three": {state: stateOK},
			},
			components: []string{"one", "two", "three"},
			want:       stateStarting,
		},
		{
			desc: "multiple components, one is missing",
			states: map[string]*componentState{
				"one":   {state: stateOK},
				"three": {state: stateOK},
			},
			components: []string{"one", "two", "three"},
			want:       stateStarting,
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			process := &TeleportProcess{components: make(map[string]bool)}
			for _, component := range tt.components {
				process.registerComponent(component)
			}
			ps := &processState{process: process, states: tt.states}
			got := ps.getState()
			require.Equal(t, got, tt.want)
		})
	}
}
