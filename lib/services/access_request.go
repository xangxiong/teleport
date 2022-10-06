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
	// GetPluginData loads all plugin data matching the supplied filter.
	GetPluginData(ctx context.Context, filter types.PluginDataFilter) ([]types.PluginData, error)
	// UpdatePluginData updates a per-resource PluginData entry.
	UpdatePluginData(ctx context.Context, params types.PluginDataUpdateParams) error
}

// DynamicAccess is a service which manages dynamic RBAC.  Specifically, this is the
// dynamic access interface implemented by remote clients.
type DynamicAccess interface {
	DynamicAccessCore
}

// DynamicAccessExt is an extended dynamic access interface
// used to implement some auth server internals.
type DynamicAccessExt interface {
	DynamicAccessCore
	// UpsertAccessRequest creates or updates an access request.
	UpsertAccessRequest(ctx context.Context, req types.AccessRequest) error
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
