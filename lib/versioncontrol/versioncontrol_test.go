/*
Copyright 2022 Gravitational, Inc.

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

package versioncontrol

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVisitorBasics(t *testing.T) {
	tts := []struct {
		versions         []string
		newest           string
		oldest           string
		permitPrerelease bool
		desc             string
	}{
		{
			versions: []string{
				"v1.2.3",
				"v2.3.4-alpha.1",
			},
			newest: "v1.2.3",
			oldest: "v1.2.3",
			desc:   "one stable release",
		},
		{
			versions: []string{
				"v1.2.3",
				"v2.3.4",
				"v2.2.2",
				"v3.5.7",
				"invalid",
				"v0.0.1-alpha.2",
			},
			newest: "v3.5.7",
			oldest: "v1.2.3",
			desc:   "mixed releases",
		},
		{
			versions: []string{
				"invalid",
				"12356",
				"127.0.0.1:8080",
			},
			desc: "all invalid",
		},
		{
			versions: []string{
				"v3.4.5-alpha.1",
				"v3.4.4",
				"v0.1.2-alpha.2",
				"v0.1.11",
			},
			newest:           "v3.4.5-alpha.1",
			oldest:           "v0.1.2-alpha.2",
			permitPrerelease: true,
			desc:             "prerelease on",
		},
		{
			versions: []string{
				"v3.4.5-alpha.1",
				"v3.4.4",
				"v0.1.2-alpha.2",
				"v0.1.11",
			},
			newest:           "v3.4.4",
			oldest:           "v0.1.11",
			permitPrerelease: false,
			desc:             "prerelease off",
		},
		{
			versions: []string{
				"v3.4.5-alpha.1",
				"v3.4.4",
				"v0.1.12-alpha.2",
				"v0.1.2",
			},
			newest:           "v3.4.5-alpha.1",
			oldest:           "v0.1.2",
			permitPrerelease: true,
			desc:             "prerelease on (mixed)",
		},
	}

	for _, tt := range tts {
		visitor := Visitor{
			PermitPrerelease: tt.permitPrerelease,
		}

		for _, v := range tt.versions {
			visitor.Visit(Target{LabelVersion: v})
		}

		require.Equal(t, tt.newest, visitor.Newest().Version(), tt.desc)
		require.Equal(t, tt.oldest, visitor.Oldest().Version(), tt.desc)
	}
}

func TestVisitorRelative(t *testing.T) {
	tts := []struct {
		current       Target
		targets       []Target
		nextMajor     Target
		newestCurrent Target
		newestSec     Target
		desc          string
	}{
		{
			current: NewTarget("v1.2.3"),
			targets: []Target{
				NewTarget("v1.3.5", SecurityPatch(true)),
				NewTarget("v2.3.4"),
				NewTarget("v2", SecurityPatch(true)),
				NewTarget("v0.1", SecurityPatch(true)),
				NewTarget("v2.4.2"),
				NewTarget("v1.4.4"),
				NewTarget("v3.4.5"),
			},
			nextMajor:     NewTarget("v2.4.2"),
			newestCurrent: NewTarget("v1.4.4"),
			newestSec:     NewTarget("v1.3.5", SecurityPatch(true)),
			desc:          "broad test case",
		},
		{
			targets: []Target{
				NewTarget("v1.3.5", SecurityPatch(true)),
				NewTarget("v2.3.4"),
				NewTarget("v2", SecurityPatch(true)),
				NewTarget("v0.1", SecurityPatch(true)),
				NewTarget("v2.4.2"),
				NewTarget("v1.4.4"),
			},
			desc: "no current target specified",
		},
		{
			current: NewTarget("v1.2.3"),
			targets: []Target{
				NewTarget("v1.1"),
				NewTarget("v1", SecurityPatch(true)),
				NewTarget("v0.1"),
			},
			newestCurrent: NewTarget("v1.1"),
			newestSec:     NewTarget("v1", SecurityPatch(true)),
			desc:          "older targets",
		},
		{
			current: NewTarget("v3.5.6"),
			targets: []Target{
				NewTarget("v1.2.3"),
				NewTarget("v2.3.4", SecurityPatch(true)),
				NewTarget("v0.1.2"),
			},
			desc: "too old",
		},
		{
			current: NewTarget("v1.2.3"),
			targets: []Target{
				NewTarget("v3.4.5"),
				NewTarget("v3", SecurityPatch(true)),
				NewTarget("v12.13.14"),
			},
			desc: "too new",
		},
		{
			current: NewTarget("v9"),
			targets: []Target{
				NewTarget("v10.0.1"),
				NewTarget("v10", SecurityPatch(true)),
				NewTarget("v9.0.1"),
				NewTarget("v9", SecurityPatch(true)),
			},
			nextMajor:     NewTarget("v10.0.1"),
			newestCurrent: NewTarget("v9.0.1"),
			newestSec:     NewTarget("v9", SecurityPatch(true)),
			desc:          "carry the one",
		},
	}

	for _, tt := range tts {
		visitor := Visitor{
			Current: tt.current,
		}

		for _, target := range tt.targets {
			visitor.Visit(target)
		}

		require.Equal(t, tt.nextMajor, visitor.NextMajor(), tt.desc)
		require.Equal(t, tt.newestCurrent, visitor.NewestCurrent(), tt.desc)
		require.Equal(t, tt.newestSec, visitor.NewestSecurityPatch(), tt.desc)
	}
}
