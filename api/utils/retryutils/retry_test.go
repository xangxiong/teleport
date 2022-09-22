/*
Copyright 2021-2022 Gravitational, Inc.

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

package retryutils

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestLinear tests retry logic
func TestLinear(t *testing.T) {
	t.Parallel()

	r, err := NewLinear(LinearConfig{
		Step: time.Second,
		Max:  3 * time.Second,
	})
	require.NoError(t, err)
	require.Equal(t, r.Duration(), time.Duration(0))
	r.Inc()
	require.Equal(t, r.Duration(), time.Second)
	r.Inc()
	require.Equal(t, r.Duration(), 2*time.Second)
	r.Inc()
	require.Equal(t, r.Duration(), 3*time.Second)
	r.Inc()
	require.Equal(t, r.Duration(), 3*time.Second)
	r.Reset()
	require.Equal(t, r.Duration(), time.Duration(0))
}

func TestLinearRetryMax(t *testing.T) {
	t.Parallel()

	cases := []struct {
		desc              string
		config            LinearConfig
		previousCompareFn require.ComparisonAssertionFunc
	}{
		{
			desc: "FullJitter",
			config: LinearConfig{
				First:  time.Second * 45,
				Step:   time.Second * 30,
				Max:    time.Minute,
				Jitter: NewFullJitter(),
			},
			previousCompareFn: require.NotEqual,
		},
		{
			desc: "HalfJitter",
			config: LinearConfig{
				First:  time.Second * 45,
				Step:   time.Second * 30,
				Max:    time.Minute,
				Jitter: NewHalfJitter(),
			},
			previousCompareFn: require.NotEqual,
		},
		{
			desc: "SeventhJitter",
			config: LinearConfig{
				First:  time.Second * 45,
				Step:   time.Second * 30,
				Max:    time.Minute,
				Jitter: NewSeventhJitter(),
			},
			previousCompareFn: require.NotEqual,
		},

		{
			desc: "NoJitter",
			config: LinearConfig{
				First: time.Second * 45,
				Step:  time.Second * 30,
				Max:   time.Minute,
			},
			previousCompareFn: require.Equal,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()
			linear, err := NewLinear(tc.config)
			require.NoError(t, err)

			// artificially spike the attempts to get to max
			linear.attempt = 100

			// get the initial previous value to compare with
			previous := linear.Duration()
			linear.Inc()

			for i := 0; i < 50; i++ {
				duration := linear.Duration()
				linear.Inc()

				// ensure duration does not exceed maximum
				require.LessOrEqual(t, duration, tc.config.Max)

				// ensure duration comparison to previous is satisfied
				tc.previousCompareFn(t, duration, previous)
			}
		})
	}
}
