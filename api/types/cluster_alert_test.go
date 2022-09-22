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

package types

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestAlertSorting verifies the default cluster alert sorting.
func TestAlertSorting(t *testing.T) {
	start := time.Now()

	aa := []struct {
		t time.Time     // creation time
		s AlertSeverity // severity
		p int           // post-sort index
	}{
		{
			t: start.Add(time.Second * 2),
			s: AlertSeverity_HIGH,
			p: 1,
		},
		{
			t: start.Add(time.Second * 1),
			s: AlertSeverity_HIGH,
			p: 2,
		},
		{
			t: start.Add(time.Second * 2),
			s: AlertSeverity_LOW,
			p: 4,
		},
		{
			t: start.Add(time.Second * 3),
			s: AlertSeverity_HIGH,
			p: 0,
		},
		{
			t: start.Add(time.Hour),
			s: AlertSeverity_MEDIUM,
			p: 3,
		},
	}

	// build the alerts
	alerts := make([]ClusterAlert, 0, len(aa))
	for i, a := range aa {
		alert, err := NewClusterAlert(
			fmt.Sprintf("alert-%d", i),
			"uh-oh!",
			WithAlertCreated(a.t),
			WithAlertSeverity(a.s),
			WithAlertLabel("p", fmt.Sprintf("%d", a.p)),
		)
		require.NoError(t, err)
		alerts = append(alerts, alert)
	}

	// apply the default sorting
	SortClusterAlerts(alerts)

	// verify that post-sort labels now match order
	for i, a := range alerts {
		require.Equal(t, fmt.Sprintf("%d", i), a.Metadata.Labels["p"])
	}
}

// TestCheckAndSetDefaults verifies that only valid URLs are set on the link label.
func TestCheckAndSetDefaultsWithLink(t *testing.T) {
	tests := []struct {
		link   string
		assert require.ErrorAssertionFunc
	}{
		{
			link:   "https://goteleport.com/docs",
			assert: require.NoError,
		},
		{
			link:   "h{t}tps://goteleport.com/docs",
			assert: require.Error,
		},
		{
			link:   "https://google.com",
			assert: require.Error,
		},
	}

	for i, tt := range tests {
		t.Run(tt.link, func(t *testing.T) {
			_, err := NewClusterAlert(
				fmt.Sprintf("name-%d", i),
				fmt.Sprintf("message-%d", i),
				WithAlertLabel(AlertLink, tt.link),
			)
			tt.assert(t, err)
		})
	}
}
