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

package local

import (
	"context"
	"time"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/services"

	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
)

const (
	sessionPrefix                 = "session_tracker"
	retryDelay      time.Duration = time.Second
	casRetryLimit   int           = 7
	casErrorMessage string        = "CompareAndSwap reached retry limit"
)

type sessionTracker struct {
	bk backend.Backend
}

func NewSessionTrackerService(bk backend.Backend) (services.SessionTrackerService, error) {
	return &sessionTracker{bk}, nil
}

func (s *sessionTracker) loadSession(ctx context.Context, sessionID string) (types.SessionTracker, error) {
	sessionJSON, err := s.bk.Get(ctx, backend.Key(sessionPrefix, sessionID))
	if err != nil {
		return nil, trace.Wrap(err)
	}

	session, err := services.UnmarshalSessionTracker(sessionJSON.Value)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return session, nil
}

// GetSessionTracker returns the current state of a session tracker for an active session.
func (s *sessionTracker) GetSessionTracker(ctx context.Context, sessionID string) (types.SessionTracker, error) {
	session, err := s.loadSession(ctx, sessionID)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return session, nil
}

// GetActiveSessionTrackers returns a list of active session trackers.
func (s *sessionTracker) GetActiveSessionTrackers(ctx context.Context) ([]types.SessionTracker, error) {
	prefix := backend.Key(sessionPrefix)
	result, err := s.bk.GetRange(ctx, prefix, backend.RangeEnd(prefix), backend.NoLimit)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	sessions := make([]types.SessionTracker, 0, len(result.Items))

	// We don't overallocate expired since cleaning up sessions here should be rare.
	var noExpiry []backend.Item
	now := s.bk.Clock().Now()
	for _, item := range result.Items {
		session, err := services.UnmarshalSessionTracker(item.Value)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		// NOTE: This is the session expiry timestamp, not the backend timestamp stored in `item.Expires`.
		exp := session.GetExpires()
		if session.Expiry().After(exp) {
			exp = session.Expiry()
		}

		after := exp.After(now)

		switch {
		case after:
			// Keep any items that aren't expired.
			sessions = append(sessions, session)
		case !after && item.Expires.IsZero():
			// Clear item if expiry is not set on the backend.
			noExpiry = append(noExpiry, item)
		default:
			// If we take this branch, the expiry is set and the backend is responsible for cleaning up the item.
		}
	}

	if len(noExpiry) > 0 {
		go func() {
			for _, item := range noExpiry {
				if err := s.bk.Delete(ctx, item.Key); err != nil {
					if !trace.IsNotFound(err) {
						logrus.WithError(err).Error("Failed to remove stale session tracker")
					}
				}
			}
		}()
	}

	return sessions, nil
}

// CreateSessionTracker creates a tracker resource for an active session.
func (s *sessionTracker) CreateSessionTracker(ctx context.Context, tracker types.SessionTracker) (types.SessionTracker, error) {
	json, err := services.MarshalSessionTracker(tracker)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	item := backend.Item{
		Key:     backend.Key(sessionPrefix, tracker.GetSessionID()),
		Value:   json,
		Expires: tracker.Expiry(),
	}
	_, err = s.bk.Put(ctx, item)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return tracker, nil
}

// UpdateSessionTracker updates a tracker resource for an active session.
func (s *sessionTracker) UpdateSessionTracker(ctx context.Context, req *proto.UpdateSessionTrackerRequest) error {
	for i := 0; i < casRetryLimit; i++ {
		sessionItem, err := s.bk.Get(ctx, backend.Key(sessionPrefix, req.SessionID))
		if err != nil {
			return trace.Wrap(err)
		}

		session, err := services.UnmarshalSessionTracker(sessionItem.Value)
		if err != nil {
			return trace.Wrap(err)
		}

		switch session := session.(type) {
		case *types.SessionTrackerV1:
			switch update := req.Update.(type) {
			case *proto.UpdateSessionTrackerRequest_UpdateState:
				session.SetState(update.UpdateState.State)
			case *proto.UpdateSessionTrackerRequest_AddParticipant:
				session.AddParticipant(*update.AddParticipant.Participant)
			case *proto.UpdateSessionTrackerRequest_RemoveParticipant:
				session.RemoveParticipant(update.RemoveParticipant.ParticipantID)
			case *proto.UpdateSessionTrackerRequest_UpdateExpiry:
				session.SetExpiry(*update.UpdateExpiry.Expires)
			}
		default:
			return trace.BadParameter("unrecognized session version %T", session)
		}

		sessionJSON, err := services.MarshalSessionTracker(session)
		if err != nil {
			return trace.Wrap(err)
		}

		item := backend.Item{
			Key:     backend.Key(sessionPrefix, req.SessionID),
			Value:   sessionJSON,
			Expires: session.Expiry(),
		}
		_, err = s.bk.CompareAndSwap(ctx, *sessionItem, item)
		if trace.IsCompareFailed(err) {
			select {
			case <-ctx.Done():
				return trace.Wrap(ctx.Err())
			case <-time.After(retryDelay):
				continue
			}
		}

		return trace.Wrap(err)
	}

	return trace.CompareFailed(casErrorMessage)
}

// RemoveSessionTracker removes a tracker resource for an active session.
func (s *sessionTracker) RemoveSessionTracker(ctx context.Context, sessionID string) error {
	return trace.Wrap(s.bk.Delete(ctx, backend.Key(sessionPrefix, sessionID)))
}
