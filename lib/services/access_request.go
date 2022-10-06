/*
Copyright 2019 Gravitational, Inc.

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

package services

import (
	"context"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/teleport/lib/utils/parse"

	"github.com/google/uuid"
	"github.com/gravitational/trace"
	"github.com/vulcand/predicate"
)

const maxAccessRequestReasonSize = 4096

// ValidateAccessRequest validates the AccessRequest and sets default values
func ValidateAccessRequest(ar types.AccessRequest) error {
	if err := ar.CheckAndSetDefaults(); err != nil {
		return trace.Wrap(err)
	}
	_, err := uuid.Parse(ar.GetName())
	if err != nil {
		return trace.BadParameter("invalid access request id %q", ar.GetName())
	}
	if len(ar.GetRequestReason()) > maxAccessRequestReasonSize {
		return trace.BadParameter("access request reason is too long, max %v bytes", maxAccessRequestReasonSize)
	}
	if len(ar.GetResolveReason()) > maxAccessRequestReasonSize {
		return trace.BadParameter("access request resolve reason is too long, max %v bytes", maxAccessRequestReasonSize)
	}
	return nil
}

// RequestIDs is a collection of IDs for privilege escalation requests.
type RequestIDs struct {
	AccessRequests []string `json:"access_requests,omitempty"`
}

func (r *RequestIDs) Marshal() ([]byte, error) {
	data, err := utils.FastMarshal(r)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return data, nil
}

func (r *RequestIDs) Unmarshal(data []byte) error {
	if err := utils.FastUnmarshal(data, r); err != nil {
		return trace.Wrap(err)
	}
	return trace.Wrap(r.Check())
}

func (r *RequestIDs) Check() error {
	for _, id := range r.AccessRequests {
		_, err := uuid.Parse(id)
		if err != nil {
			return trace.BadParameter("invalid request id %q", id)
		}
	}
	return nil
}

func (r *RequestIDs) IsEmpty() bool {
	return len(r.AccessRequests) < 1
}

// DynamicAccessCore is the core functionality common to all DynamicAccess implementations.
type DynamicAccessCore interface {
	// CreateAccessRequest stores a new access request.
	CreateAccessRequest(ctx context.Context, req types.AccessRequest) error
	// GetAccessRequests gets all currently active access requests.
	GetAccessRequests(ctx context.Context, filter types.AccessRequestFilter) ([]types.AccessRequest, error)
	// DeleteAccessRequest deletes an access request.
	DeleteAccessRequest(ctx context.Context, reqID string) error
	// GetPluginData loads all plugin data matching the supplied filter.
	GetPluginData(ctx context.Context, filter types.PluginDataFilter) ([]types.PluginData, error)
	// UpdatePluginData updates a per-resource PluginData entry.
	UpdatePluginData(ctx context.Context, params types.PluginDataUpdateParams) error
}

// DynamicAccess is a service which manages dynamic RBAC.  Specifically, this is the
// dynamic access interface implemented by remote clients.
type DynamicAccess interface {
	DynamicAccessCore
	// SetAccessRequestState updates the state of an existing access request.
	SetAccessRequestState(ctx context.Context, params types.AccessRequestUpdate) error
}

// DynamicAccessExt is an extended dynamic access interface
// used to implement some auth server internals.
type DynamicAccessExt interface {
	DynamicAccessCore
	// UpsertAccessRequest creates or updates an access request.
	UpsertAccessRequest(ctx context.Context, req types.AccessRequest) error
	// DeleteAllAccessRequests deletes all existent access requests.
	DeleteAllAccessRequests(ctx context.Context) error
	// SetAccessRequestState updates the state of an existing access request.
	SetAccessRequestState(ctx context.Context, params types.AccessRequestUpdate) (types.AccessRequest, error)
}

// reviewParamsContext is a simplified view of an access review
// which represents the incoming review during review threshold
// filter evaluation.
type reviewParamsContext struct {
	Reason      string              `json:"reason"`
	Annotations map[string][]string `json:"annotations"`
}

// reviewAuthorContext is a simplified view of a user
// resource which represents the author of a review during
// review threshold filter evaluation.
type reviewAuthorContext struct {
	Roles  []string            `json:"roles"`
	Traits map[string][]string `json:"traits"`
}

// reviewRequestContext is a simplified view of an access request
// resource which represents the request parameters which are in-scope
// during review threshold filter evaluation.
type reviewRequestContext struct {
	Roles             []string            `json:"roles"`
	Reason            string              `json:"reason"`
	SystemAnnotations map[string][]string `json:"system_annotations"`
}

// thresholdFilterContext is the top-level context used to evaluate
// review threshold filters.
type thresholdFilterContext struct {
	Reviewer reviewAuthorContext  `json:"reviewer"`
	Review   reviewParamsContext  `json:"review"`
	Request  reviewRequestContext `json:"request"`
}

// reviewPermissionContext is the top-level context used to evaluate
// a user's review permissions.  It is functionally identical to the
// thresholdFilterContext except that it does not expose review parameters.
// this is because review permissions are used to determine which requests
// a user is allowed to see, and therefore needs to be calculable prior
// to construction of review parameters.
type reviewPermissionContext struct {
	Reviewer reviewAuthorContext  `json:"reviewer"`
	Request  reviewRequestContext `json:"request"`
}

// checkReviewCompat performs basic checks to ensure that the specified review can be
// applied to the specified request (part of review application logic).
func checkReviewCompat(req types.AccessRequest, rev types.AccessReview) error {
	// we currently only support reviews that propose approval/denial.  future iterations
	// may support additional states (e.g. None for comment-only reviews).
	if !rev.ProposedState.IsApproved() && !rev.ProposedState.IsDenied() {
		return trace.BadParameter("invalid state proposal: %s (expected approval/denial)", rev.ProposedState)
	}

	// the default threshold should exist. if it does not, the request either is not fully
	// initialized (i.e. variable expansion has not been run yet) or the request was inserted into
	// the backend by a teleport instance which does not support the review feature.
	if len(req.GetThresholds()) == 0 {
		return trace.BadParameter("request is uninitialized or does not support reviews")
	}

	// user must not have previously reviewed this request
	for _, existingReview := range req.GetReviews() {
		if existingReview.Author == rev.Author {
			return trace.AccessDenied("user %q has already reviewed this request", rev.Author)
		}
	}

	rtm := req.GetRoleThresholdMapping()

	// TODO(fspmarshall): Remove this restriction once role overrides
	// in reviews are fully supported.
	if len(rev.Roles) != 0 && len(rev.Roles) != len(rtm) {
		return trace.NotImplemented("role subselection is not yet supported in reviews, try omitting role list")
	}

	// TODO(fspmarhsall): Remove this restriction once annotations
	// in reviews are fully supported.
	if len(rev.Annotations) != 0 {
		return trace.NotImplemented("annotations are not yet supported in reviews, try omitting annotations field")
	}

	// verify that all roles are present within the request
	for _, role := range rev.Roles {
		if _, ok := rtm[role]; !ok {
			return trace.BadParameter("role %q is not a member of this request", role)
		}
	}

	return nil
}

// collectReviewThresholdIndexes aggregates the indexes of all thresholds whose filters match
// the supplied review (part of review application logic).
func collectReviewThresholdIndexes(req types.AccessRequest, rev types.AccessReview, author types.User) ([]uint32, error) {
	parser, err := newThresholdFilterParser(req, rev, author)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var tids []uint32

	for i, t := range req.GetThresholds() {
		match, err := accessReviewThresholdMatchesFilter(t, parser)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		if !match {
			continue
		}

		tid := uint32(i)
		if int(tid) != i {
			// sanity-check.  we disallow extremely large threshold lists elsewhere, but it's always
			// best to double-check these things.
			return nil, trace.Errorf("threshold index %d out of supported range (this is a bug)", i)
		}
		tids = append(tids, tid)
	}

	return tids, nil
}

// accessReviewThresholdMatchesFilter returns true if Filter rule matches
// Empty Filter block always matches
func accessReviewThresholdMatchesFilter(t types.AccessReviewThreshold, parser predicate.Parser) (bool, error) {
	if t.Filter == "" {
		return true, nil
	}
	ifn, err := parser.Parse(t.Filter)
	if err != nil {
		return false, trace.Wrap(err)
	}
	fn, ok := ifn.(predicate.BoolPredicate)
	if !ok {
		return false, trace.BadParameter("unsupported type: %T", ifn)
	}
	return fn(), nil
}

// newThresholdFilterParser creates a custom parser context which exposes a simplified view of the review author
// and the request for evaluation of review threshold filters.
func newThresholdFilterParser(req types.AccessRequest, rev types.AccessReview, author types.User) (BoolPredicateParser, error) {
	return NewJSONBoolParser(thresholdFilterContext{
		Reviewer: reviewAuthorContext{
			Roles:  author.GetRoles(),
			Traits: author.GetTraits(),
		},
		Review: reviewParamsContext{
			Reason:      rev.Reason,
			Annotations: rev.Annotations,
		},
		Request: reviewRequestContext{
			Roles:             req.GetOriginalRoles(),
			Reason:            req.GetRequestReason(),
			SystemAnnotations: req.GetSystemAnnotations(),
		},
	})
}

// requestResolution describes a request state-transition from
// PENDING to some other state.
type requestResolution struct {
	state  types.RequestState
	reason string
}

// calculateReviewBasedResolution calculates the request resolution based upon
// a request's reviews.  Returns (nil,nil) in the event no resolution has been reached.
func calculateReviewBasedResolution(req types.AccessRequest) (*requestResolution, error) {
	// thresholds and reviews must be populated before state-transitions are possible
	thresholds, reviews := req.GetThresholds(), req.GetReviews()
	if len(thresholds) == 0 || len(reviews) == 0 {
		return nil, nil
	}

	// approved keeps track of roles that have hit at least one
	// of their approval thresholds.
	approved := make(map[string]struct{})

	// denied keeps track of whether or not we've seen *any* role get denied
	// (which role does not currently matter since we short-circuit on the
	// first denial to be triggered).
	denied := false

	// counts keeps track of the approval and denial counts for all thresholds.
	counts := make([]struct{ approval, denial uint32 }, len(thresholds))

	// lastReview stores the most recently processed review.  Since processing halts
	// once we hit our first approval/denial condition, this review represents the
	// triggering review for the approval/denial state-transition.
	var lastReview types.AccessReview

	// Iterate through all reviews and aggregate them against `counts`.
ProcessReviews:
	for _, rev := range reviews {
		lastReview = rev
		for _, tid := range rev.ThresholdIndexes {
			idx := int(tid)
			if len(thresholds) <= idx {
				return nil, trace.Errorf("threshold index '%d' out of range (this is a bug)", idx)
			}
			switch {
			case rev.ProposedState.IsApproved():
				counts[idx].approval++
			case rev.ProposedState.IsDenied():
				counts[idx].denial++
			default:
				return nil, trace.BadParameter("cannot calculate state-transition, unexpected proposal: %s", rev.ProposedState)
			}
		}

		// If we hit any denial thresholds, short-circuit immediately
		for i, t := range thresholds {

			if counts[i].denial >= t.Deny && t.Deny != 0 {
				denied = true
				break ProcessReviews
			}
		}

		// check for roles that can be transitioned to an approved state
	CheckRoleApprovals:
		for role, thresholdSets := range req.GetRoleThresholdMapping() {
			if _, ok := approved[role]; ok {
				// role was marked approved during a previous iteration
				continue CheckRoleApprovals
			}

			// iterate through all threshold sets.  All sets must have at least
			// one threshold which has hit its approval count in order for the
			// role to be considered approved.
		CheckThresholdSets:
			for _, tset := range thresholdSets.Sets {

				for _, tid := range tset.Indexes {
					idx := int(tid)
					if len(thresholds) <= idx {
						return nil, trace.Errorf("threshold index out of range %s/%d (this is a bug)", role, tid)
					}
					t := thresholds[idx]

					if counts[idx].approval >= t.Approve && t.Approve != 0 {
						// this set contains a threshold which has met its approval condition.
						// skip to the next set.
						continue CheckThresholdSets
					}
				}

				// no thresholds met for this set. there may be additional roles/thresholds
				// which did meet their requirements this iteration, but there is no point
				// processing them unless this set has also hit its requirements.  we therefore
				// move immediately to processing the next review.
				continue ProcessReviews
			}

			// since we skip to the next review as soon as we see a set which has not hit any of its
			// approval scenarios, we know that if we get to this point the role must be approved.
			approved[role] = struct{}{}
		}
		// If we got here, then we iterated across all roles in the rtm without hitting any that
		// had not met their approval scenario.  The request has hit an approved state and further
		// reviews will not be processed.
		break ProcessReviews
	}

	switch {
	case lastReview.ProposedState.IsApproved():
		if len(approved) != len(req.GetRoleThresholdMapping()) {
			// processing halted on approval, but not all roles have
			// hit their approval thresholds; no state-transition.
			return nil, nil
		}
	case lastReview.ProposedState.IsDenied():
		if !denied {
			// processing halted on denial, but no roles have hit
			// their denial thresholds; no state-transition.
			return nil, nil
		}
	default:
		return nil, trace.BadParameter("cannot calculate state-transition, unexpected proposal: %s", lastReview.ProposedState)
	}

	// processing halted on valid state-transition; return resolution
	// based on last review
	return &requestResolution{
		state:  lastReview.ProposedState,
		reason: lastReview.Reason,
	}, nil
}

// ReviewPermissionChecker is a helper for validating whether or not a user
// is allowed to review specific access requests.
type ReviewPermissionChecker struct {
	User  types.User
	Roles struct {
		// allow/deny mappings sort role matches into lists based on their
		// constraining predicate (where) expression.
		AllowReview, DenyReview map[string][]parse.Matcher
	}
}

// CanReviewRequest checks if the user is allowed to review the specified request.
// note that the ability to review a request does not necessarily imply that any specific
// approval/denial thresholds will actually match the user's review.  Matching one or more
// thresholds is not a pre-requisite for review submission.
func (c *ReviewPermissionChecker) CanReviewRequest(req types.AccessRequest) (bool, error) {
	// TODO(fspmarshall): Refactor this to improve readability when
	// adding role subselection support.

	// user cannot review their own request
	if c.User.GetName() == req.GetUser() {
		return false, nil
	}

	// method allocates new array if an override has already been
	// called, so get the role list once in advance.
	requestedRoles := req.GetOriginalRoles()

	parser, err := NewJSONBoolParser(reviewPermissionContext{
		Reviewer: reviewAuthorContext{
			Roles:  c.User.GetRoles(),
			Traits: c.User.GetTraits(),
		},
		Request: reviewRequestContext{
			Roles:             requestedRoles,
			Reason:            req.GetRequestReason(),
			SystemAnnotations: req.GetSystemAnnotations(),
		},
	})
	if err != nil {
		return false, trace.Wrap(err)
	}

	// check all denial rules first.
	for expr, denyMatchers := range c.Roles.DenyReview {
		// if predicate is non-empty, it must match
		if expr != "" {
			match, err := parser.EvalBoolPredicate(expr)
			if err != nil {
				return false, trace.Wrap(err)
			}
			if !match {
				continue
			}
		}

		for _, role := range requestedRoles {
			for _, deny := range denyMatchers {
				if deny.Match(role) {
					// short-circuit on first denial
					return false, nil
				}
			}
		}
	}

	// needsAllow tracks the list of roles which still need to match an allow directive
	// in order for the request to be reviewable.  we need to perform a deep copy here
	// since we perform a filter-in-place when we find a matching allow directive.
	needsAllow := make([]string, len(requestedRoles))
	copy(needsAllow, requestedRoles)

Outer:
	for expr, allowMatchers := range c.Roles.AllowReview {
		// if predicate is non-empty, it must match.
		if expr != "" {
			match, err := parser.EvalBoolPredicate(expr)
			if err != nil {
				return false, trace.Wrap(err)
			}
			if !match {
				continue Outer
			}
		}

		// unmatched collects unmatched roles for our filter-in-place operation.
		unmatched := needsAllow[:0]

	MatchRoles:
		for _, role := range needsAllow {
			for _, allow := range allowMatchers {
				if allow.Match(role) {
					// role matched this allow directive, and will be filtered out
					continue MatchRoles
				}
			}

			// still unmatched, this role will continue to be part of
			// the needsAllow list next iteration.
			unmatched = append(unmatched, role)
		}

		// finalize our filter-in-place
		needsAllow = unmatched

		if len(needsAllow) == 0 {
			// all roles have matched an allow directive, no further
			// processing is required.
			break Outer
		}
	}

	return len(needsAllow) == 0, nil
}

// UnmarshalAccessRequest unmarshals the AccessRequest resource from JSON.
func UnmarshalAccessRequest(data []byte, opts ...MarshalOption) (types.AccessRequest, error) {
	cfg, err := CollectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var req types.AccessRequestV3
	if err := utils.FastUnmarshal(data, &req); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := ValidateAccessRequest(&req); err != nil {
		return nil, trace.Wrap(err)
	}
	if cfg.ID != 0 {
		req.SetResourceID(cfg.ID)
	}
	if !cfg.Expires.IsZero() {
		req.SetExpiry(cfg.Expires)
	}
	return &req, nil
}

// MarshalAccessRequest marshals the AccessRequest resource to JSON.
func MarshalAccessRequest(accessRequest types.AccessRequest, opts ...MarshalOption) ([]byte, error) {
	if err := ValidateAccessRequest(accessRequest); err != nil {
		return nil, trace.Wrap(err)
	}

	cfg, err := CollectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	switch accessRequest := accessRequest.(type) {
	case *types.AccessRequestV3:
		if !cfg.PreserveResourceID {
			// avoid modifying the original object
			// to prevent unexpected data races
			copy := *accessRequest
			copy.SetResourceID(0)
			accessRequest = &copy
		}
		return utils.FastMarshal(accessRequest)
	default:
		return nil, trace.BadParameter("unrecognized access request type: %T", accessRequest)
	}
}
