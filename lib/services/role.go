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

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/types/wrappers"
	apiutils "github.com/gravitational/teleport/api/utils"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/teleport/lib/utils/parse"

	"github.com/gravitational/configure/cstrings"
	"github.com/gravitational/trace"

	log "github.com/sirupsen/logrus"
)

// DefaultImplicitRules provides access to the default set of implicit rules
// assigned to all roles.
var DefaultImplicitRules = []types.Rule{
	types.NewRule(types.KindNode, RO()),
	types.NewRule(types.KindProxy, RO()),
	types.NewRule(types.KindAuthServer, RO()),
	types.NewRule(types.KindReverseTunnel, RO()),
	types.NewRule(types.KindCertAuthority, ReadNoSecrets()),
	types.NewRule(types.KindClusterAuthPreference, RO()),
	types.NewRule(types.KindClusterName, RO()),
	types.NewRule(types.KindSSHSession, RO()),
	types.NewRule(types.KindRemoteCluster, RO()),
}

// ErrSessionMFARequired is returned by AccessChecker when access to a resource
// requires an MFA check.
var ErrSessionMFARequired = trace.AccessDenied("access to resource requires MFA")

// NewImplicitRole is the default implicit role that gets added to all
// RoleSets.
func NewImplicitRole() types.Role {
	return &types.RoleV5{
		Kind:    types.KindRole,
		Version: types.V3,
		Metadata: types.Metadata{
			Name:      constants.DefaultImplicitRole,
			Namespace: defaults.Namespace,
		},
		Spec: types.RoleSpecV5{
			Options: types.RoleOptions{
				MaxSessionTTL: types.MaxDuration(),
				// Explicitly disable options that default to true, otherwise the option
				// will always be enabled, as this implicit role is part of every role set.
				PortForwarding: types.NewBoolOption(false),
				RecordSession:  &types.RecordSession{},
			},
			Allow: types.RoleConditions{
				Namespaces: []string{defaults.Namespace},
				Rules:      types.CopyRulesSlice(DefaultImplicitRules),
			},
		},
	}
}

// ValidateRoleName checks that the role name is allowed to be created.
func ValidateRoleName(role types.Role) error {
	// System role names are not allowed.
	systemRoles := types.SystemRoles([]types.SystemRole{
		types.SystemRole(role.GetMetadata().Name),
	})
	if err := systemRoles.Check(); err == nil {
		return trace.BadParameter("reserved role: %s", role.GetMetadata().Name)
	}
	return nil
}

// ValidateRole parses validates the role, and sets default values.
func ValidateRole(r types.Role) error {
	if err := r.CheckAndSetDefaults(); err != nil {
		return err
	}

	// if we find {{ or }} but the syntax is invalid, the role is invalid
	for _, condition := range []types.RoleConditionType{types.Allow, types.Deny} {
		for _, login := range r.GetLogins(condition) {
			if strings.Contains(login, "{{") || strings.Contains(login, "}}") {
				_, err := parse.NewExpression(login)
				if err != nil {
					return trace.BadParameter("invalid login found: %v", login)
				}
			}
		}
	}

	rules := append(r.GetRules(types.Allow), r.GetRules(types.Deny)...)
	for _, rule := range rules {
		if err := validateRule(rule); err != nil {
			return trace.Wrap(err)
		}
	}

	return nil
}

// validateRule parses the where and action fields to validate the rule.
func validateRule(r types.Rule) error {
	if len(r.Where) != 0 {
		parser, err := NewWhereParser(&Context{})
		if err != nil {
			return trace.Wrap(err)
		}
		_, err = parser.Parse(r.Where)
		if err != nil {
			return trace.BadParameter("could not parse 'where' rule: %q, error: %v", r.Where, err)
		}
	}

	if len(r.Actions) != 0 {
		parser, err := NewActionsParser(&Context{})
		if err != nil {
			return trace.Wrap(err)
		}
		for i, action := range r.Actions {
			_, err = parser.Parse(action)
			if err != nil {
				return trace.BadParameter("could not parse action %v %q, error: %v", i, action, err)
			}
		}
	}
	return nil
}

func filterInvalidUnixLogins(candidates []string) []string {
	// The tests for `ApplyTraits()` require that an empty list is nil
	// rather than a 0-size slice, and I don't understand the potential
	// knock-on effects of changing that, so the  default value is `nil`
	output := []string(nil)

	for _, candidate := range candidates {
		if !cstrings.IsValidUnixUser(candidate) {
			log.Debugf("Skipping login %v, not a valid Unix login.", candidate)
			continue
		}

		// A valid variable was found in the traits, append it to the list of logins.
		output = append(output, candidate)
	}
	return output
}

// ApplyTraits applies the passed in traits to any variables within the role
// and returns itself.
func ApplyTraits(r types.Role, traits map[string][]string) types.Role {
	for _, condition := range []types.RoleConditionType{types.Allow, types.Deny} {
		inLogins := r.GetLogins(condition)
		outLogins := applyValueTraitsSlice(inLogins, traits, "login")
		outLogins = filterInvalidUnixLogins(outLogins)
		r.SetLogins(condition, apiutils.Deduplicate(outLogins))

		// apply templates to node labels
		inLabels := r.GetNodeLabels(condition)
		if inLabels != nil {
			r.SetNodeLabels(condition, applyLabelsTraits(inLabels, traits))
		}

		// apply templates to cluster labels
		inLabels = r.GetClusterLabels(condition)
		if inLabels != nil {
			r.SetClusterLabels(condition, applyLabelsTraits(inLabels, traits))
		}

		r.SetHostGroups(condition,
			applyValueTraitsSlice(r.GetHostGroups(condition), traits, "host_groups"))

		r.SetHostSudoers(condition,
			applyValueTraitsSlice(r.GetHostSudoers(condition), traits, "host_sudoers"))

		options := r.GetOptions()
		for i, ext := range options.CertExtensions {
			vals, err := ApplyValueTraits(ext.Value, traits)
			if err != nil && !trace.IsNotFound(err) {
				log.Warnf("Did not apply trait to cert_extensions.value: %v", err)
				continue
			}
			if len(vals) != 0 {
				options.CertExtensions[i].Value = vals[0]
			}
		}

		// apply templates to impersonation conditions
		inCond := r.GetImpersonateConditions(condition)
		var outCond types.ImpersonateConditions
		outCond.Users = applyValueTraitsSlice(inCond.Users, traits, "impersonate user")
		outCond.Roles = applyValueTraitsSlice(inCond.Roles, traits, "impersonate role")
		outCond.Users = apiutils.Deduplicate(outCond.Users)
		outCond.Roles = apiutils.Deduplicate(outCond.Roles)
		outCond.Where = inCond.Where
		r.SetImpersonateConditions(condition, outCond)
	}

	return r
}

// applyValueTraitsSlice iterates over a slice of input strings, calling
// ApplyValueTraits on each.
func applyValueTraitsSlice(inputs []string, traits map[string][]string, fieldName string) []string {
	var output []string
	for _, value := range inputs {
		outputs, err := ApplyValueTraits(value, traits)
		if err != nil {
			if !trace.IsNotFound(err) {
				log.WithError(err).Debugf("Skipping %s %q.", fieldName, value)
			}
			continue
		}
		output = append(output, outputs...)
	}
	return output
}

// applyLabelsTraits interpolates variables based on the templates
// and traits from identity provider. For example:
//
// cluster_labels:
//
//	env: ['{{external.groups}}']
//
// and groups: ['admins', 'devs']
//
// will be interpolated to:
//
// cluster_labels:
//
//	env: ['admins', 'devs']
func applyLabelsTraits(inLabels types.Labels, traits map[string][]string) types.Labels {
	outLabels := make(types.Labels, len(inLabels))
	// every key will be mapped to the first value
	for key, vals := range inLabels {
		keyVars, err := ApplyValueTraits(key, traits)
		if err != nil {
			// empty key will not match anything
			log.Debugf("Setting empty node label pair %q -> %q: %v", key, vals, err)
			keyVars = []string{""}
		}

		var values []string
		for _, val := range vals {
			valVars, err := ApplyValueTraits(val, traits)
			if err != nil {
				log.Debugf("Setting empty node label value %q -> %q: %v", key, val, err)
				// empty value will not match anything
				valVars = []string{""}
			}
			values = append(values, valVars...)
		}
		outLabels[keyVars[0]] = apiutils.Deduplicate(values)
	}
	return outLabels
}

// ApplyValueTraits applies the passed in traits to the variable,
// returns BadParameter in case if referenced variable is unsupported,
// returns NotFound in case if referenced trait is missing,
// mapped list of values otherwise, the function guarantees to return
// at least one value in case if return value is nil
func ApplyValueTraits(val string, traits map[string][]string) ([]string, error) {
	// Extract the variable from the role variable.
	variable, err := parse.NewExpression(val)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// verify that internal traits match the supported variables
	if variable.Namespace() == teleport.TraitInternalPrefix {
		switch variable.Name() {
		case constants.TraitLogins, teleport.TraitJWT:
		default:
			return nil, trace.BadParameter("unsupported variable %q", variable.Name())
		}
	}

	// If the variable is not found in the traits, skip it.
	interpolated, err := variable.Interpolate(traits)
	if trace.IsNotFound(err) || len(interpolated) == 0 {
		return nil, trace.NotFound("variable %q not found in traits", variable.Name())
	}
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return interpolated, nil
}

// ruleScore is a sorting score of the rule, the larger the score, the more
// specific the rule is
func ruleScore(r *types.Rule) int {
	score := 0
	// wildcard rules are less specific
	if apiutils.SliceContainsStr(r.Resources, types.Wildcard) {
		score -= 4
	} else if len(r.Resources) == 1 {
		// rules that match specific resource are more specific than
		// fields that match several resources
		score += 2
	}
	// rules that have wildcard verbs are less specific
	if apiutils.SliceContainsStr(r.Verbs, types.Wildcard) {
		score -= 2
	}
	// rules that supply 'where' or 'actions' are more specific
	// having 'where' or 'actions' is more important than
	// whether the rules are wildcard or not, so here we have +8 vs
	// -4 and -2 score penalty for wildcards in resources and verbs
	if len(r.Where) > 0 {
		score += 8
	}
	// rules featuring actions are more specific
	if len(r.Actions) > 0 {
		score += 8
	}
	return score
}

// CompareRuleScore returns true if the first rule is more specific than the other.
//
// * nRule matching wildcard resource is less specific
// than same rule matching specific resource.
// * Rule that has wildcard verbs is less specific
// than the same rules matching specific verb.
// * Rule that has where section is more specific
// than the same rule without where section.
// * Rule that has actions list is more specific than
// rule without actions list.
func CompareRuleScore(r *types.Rule, o *types.Rule) bool {
	return ruleScore(r) > ruleScore(o)
}

// RuleSet maps resource to a set of rules defined for it
type RuleSet map[string][]types.Rule

// MakeRuleSet creates a new rule set from a list
func MakeRuleSet(rules []types.Rule) RuleSet {
	set := make(RuleSet)
	for _, rule := range rules {
		for _, resource := range rule.Resources {
			set[resource] = append(set[resource], rule)
		}
	}
	for resource := range set {
		rules := set[resource]
		// sort rules by most specific rule, the rule that has actions
		// is more specific than the one that has no actions
		sort.Slice(rules, func(i, j int) bool {
			return CompareRuleScore(&rules[i], &rules[j])
		})
		set[resource] = rules
	}
	return set
}

// HostUsersInfo keeps information about groups and sudoers entries
// for a particular host user
type HostUsersInfo struct {
	// Groups is the list of groups to include host users in
	Groups []string
	// Sudoers is a list of entries for a users sudoers file
	Sudoers []string
}

// RoleFromSpec returns new Role created from spec
func RoleFromSpec(name string, spec types.RoleSpecV5) (types.Role, error) {
	role, err := types.NewRoleV3(name, spec)
	return role, trace.Wrap(err)
}

// RW is a shortcut that returns all verbs.
func RW() []string {
	return []string{types.VerbList, types.VerbCreate, types.VerbRead, types.VerbUpdate, types.VerbDelete}
}

// RO is a shortcut that returns read only verbs that provide access to secrets.
func RO() []string {
	return []string{types.VerbList, types.VerbRead}
}

// ReadNoSecrets is a shortcut that returns read only verbs that do not
// provide access to secrets.
func ReadNoSecrets() []string {
	return []string{types.VerbList, types.VerbReadNoSecrets}
}

// RoleGetter is an interface that defines GetRole method
type RoleGetter interface {
	// GetRole returns role by name
	GetRole(ctx context.Context, name string) (types.Role, error)
}

// FetchRoleList fetches roles by their names, applies the traits to role
// variables, and returns the list
func FetchRoleList(roleNames []string, access RoleGetter, traits map[string][]string) (RoleSet, error) {
	var roles []types.Role

	for _, roleName := range roleNames {
		role, err := access.GetRole(context.TODO(), roleName)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		roles = append(roles, ApplyTraits(role, traits))
	}

	return roles, nil
}

// FetchRoles fetches roles by their names, applies the traits to role
// variables, and returns the RoleSet. Adds runtime roles like the default
// implicit role to RoleSet.
func FetchRoles(roleNames []string, access RoleGetter, traits map[string][]string) (RoleSet, error) {
	roles, err := FetchRoleList(roleNames, access, traits)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return NewRoleSet(roles...), nil
}

// ExtractRolesFromCert extracts roles from certificate metadata extensions.
func ExtractRolesFromCert(cert *ssh.Certificate) ([]string, error) {
	data, ok := cert.Extensions[teleport.CertExtensionTeleportRoles]
	if !ok {
		return nil, trace.NotFound("no roles found")
	}
	return UnmarshalCertRoles(data)
}

// ExtractTraitsFromCert extracts traits from the certificate extensions.
func ExtractTraitsFromCert(cert *ssh.Certificate) (wrappers.Traits, error) {
	rawTraits, ok := cert.Extensions[teleport.CertExtensionTeleportTraits]
	if !ok {
		return nil, trace.NotFound("no traits found")
	}
	var traits wrappers.Traits
	err := wrappers.UnmarshalTraits([]byte(rawTraits), &traits)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return traits, nil
}

func ExtractAllowedResourcesFromCert(cert *ssh.Certificate) ([]types.ResourceID, error) {
	allowedResourcesStr, ok := cert.Extensions[teleport.CertExtensionAllowedResources]
	if !ok {
		// if not present in the cert, there are no resource-based restrictions
		return nil, nil
	}
	allowedResources, err := types.ResourceIDsFromString(allowedResourcesStr)
	return allowedResources, trace.Wrap(err)
}

// NewRoleSet returns new RoleSet based on the roles
func NewRoleSet(roles ...types.Role) RoleSet {
	// unauthenticated Nop role should not have any privileges
	// by default, otherwise it is too permissive
	if len(roles) == 1 && roles[0].GetName() == string(types.RoleNop) {
		return roles
	}
	return append(roles, NewImplicitRole())
}

// RoleSet is a set of roles that implements access control functionality
type RoleSet []types.Role

// MatchNamespace returns true if given list of namespace matches
// target namespace, wildcard matches everything.
func MatchNamespace(selectors []string, namespace string) (bool, string) {
	for _, n := range selectors {
		if n == namespace || n == types.Wildcard {
			return true, "matched"
		}
	}
	return false, fmt.Sprintf("no match, role selectors %v, server namespace: %v", selectors, namespace)
}

// MatchLabels matches selector against target. Empty selector matches
// nothing, wildcard matches everything.
func MatchLabels(selector types.Labels, target map[string]string) (bool, string, error) {
	// Empty selector matches nothing.
	if len(selector) == 0 {
		return false, "no match, empty selector", nil
	}

	// *: * matches everything even empty target set.
	selectorValues := selector[types.Wildcard]
	if len(selectorValues) == 1 && selectorValues[0] == types.Wildcard {
		return true, "matched", nil
	}

	// Perform full match.
	for key, selectorValues := range selector {
		targetVal, hasKey := target[key]

		if !hasKey {
			return false, fmt.Sprintf("no key match: '%v'", key), nil
		}

		if !apiutils.SliceContainsStr(selectorValues, types.Wildcard) {
			result, err := utils.SliceMatchesRegex(targetVal, selectorValues)
			if err != nil {
				return false, "", trace.Wrap(err)
			} else if !result {
				return false, fmt.Sprintf("no value match: got '%v' want: '%v'", targetVal, selectorValues), nil
			}
		}
	}

	return true, "matched", nil
}

// RoleNames returns a slice with role names. Removes runtime roles like
// the default implicit role.
func (set RoleSet) RoleNames() []string {
	out := make([]string, 0, len(set))
	for _, r := range set {
		if r.GetName() == constants.DefaultImplicitRole {
			continue
		}
		out = append(out, r.GetName())
	}
	return out
}

// Roles returns the list underlying roles this RoleSet is based on.
func (set RoleSet) Roles() []types.Role {
	return append([]types.Role{}, set...)
}

// HasRole checks if the role set has the role
func (set RoleSet) HasRole(role string) bool {
	for _, r := range set {
		if r.GetName() == role {
			return true
		}
	}
	return false
}

// AdjustSessionTTL will reduce the requested ttl to the lowest max allowed TTL
// for this role set, otherwise it returns ttl unchanged
func (set RoleSet) AdjustSessionTTL(ttl time.Duration) time.Duration {
	for _, role := range set {
		maxSessionTTL := role.GetOptions().MaxSessionTTL.Value()
		if maxSessionTTL != 0 && ttl > maxSessionTTL {
			ttl = maxSessionTTL
		}
	}
	return ttl
}

// MaxConnections returns the maximum number of concurrent ssh connections
// allowed.  If MaxConnections is zero then no maximum was defined
// and the number of concurrent connections is unconstrained.
func (set RoleSet) MaxConnections() int64 {
	var mcs int64
	for _, role := range set {
		if m := role.GetOptions().MaxConnections; m != 0 && (m < mcs || mcs == 0) {
			mcs = m
		}
	}
	return mcs
}

// MaxSessions returns the maximum number of concurrent ssh sessions
// per connection.  If MaxSessions is zero then no maximum was defined
// and the number of sessions is unconstrained.
func (set RoleSet) MaxSessions() int64 {
	var ms int64
	for _, role := range set {
		if m := role.GetOptions().MaxSessions; m != 0 && (m < ms || ms == 0) {
			ms = m
		}
	}
	return ms
}

// SessionPolicySets returns the list of SessionPolicySets for all roles.
func (set RoleSet) SessionPolicySets() []*types.SessionTrackerPolicySet {
	var policySets []*types.SessionTrackerPolicySet
	for _, role := range set {
		policySet := role.GetSessionPolicySet()
		policySets = append(policySets, &policySet)
	}
	return policySets
}

// AdjustClientIdleTimeout adjusts requested idle timeout
// to the lowest max allowed timeout, the most restrictive
// option will be picked, negative values will be assumed as 0
func (set RoleSet) AdjustClientIdleTimeout(timeout time.Duration) time.Duration {
	if timeout < 0 {
		timeout = 0
	}
	for _, role := range set {
		roleTimeout := role.GetOptions().ClientIdleTimeout
		// 0 means not set, so it can't be most restrictive, disregard it too
		if roleTimeout.Duration() <= 0 {
			continue
		}
		switch {
		// in case if timeout is 0, means that incoming value
		// does not restrict the idle timeout, pick any other value
		// set by the role
		case timeout == 0:
			timeout = roleTimeout.Duration()
		case roleTimeout.Duration() < timeout:
			timeout = roleTimeout.Duration()
		}
	}
	return timeout
}

// AdjustDisconnectExpiredCert adjusts the value based on the role set
// the most restrictive option will be picked
func (set RoleSet) AdjustDisconnectExpiredCert(disconnect bool) bool {
	for _, role := range set {
		if role.GetOptions().DisconnectExpiredCert.Value() {
			disconnect = true
		}
	}
	return disconnect
}

// CheckAccessToRemoteCluster checks if a role has access to remote cluster. Deny rules are
// checked first then allow rules. Access to a cluster is determined by
// namespaces, labels, and logins.
func (set RoleSet) CheckAccessToRemoteCluster(rc types.RemoteCluster) error {
	if len(set) == 0 {
		return trace.AccessDenied("access to cluster denied")
	}

	// Note: logging in this function only happens in debug mode, this is because
	// adding logging to this function (which is called on every server returned
	// by GetRemoteClusters) can slow down this function by 50x for large clusters!
	isDebugEnabled, debugf := rbacDebugLogger()

	rcLabels := rc.GetMetadata().Labels

	// For backwards compatibility, if there is no role in the set with labels and the cluster
	// has no labels, assume that the role set has access to the cluster.
	usesLabels := false
	for _, role := range set {
		if len(role.GetClusterLabels(types.Allow)) != 0 || len(role.GetClusterLabels(types.Deny)) != 0 {
			usesLabels = true
			break
		}
	}

	if !usesLabels && len(rcLabels) == 0 {
		debugf("Grant access to cluster %v - no role in %v uses cluster labels and the cluster is not labeled.",
			rc.GetName(), set.RoleNames())
		return nil
	}

	// Check deny rules first: a single matching label from
	// the deny role set prohibits access.
	var errs []error
	for _, role := range set {
		matchLabels, labelsMessage, err := MatchLabels(role.GetClusterLabels(types.Deny), rcLabels)
		if err != nil {
			return trace.Wrap(err)
		}
		if matchLabels {
			// This condition avoids formatting calls on large scale.
			debugf("Access to cluster %v denied, deny rule in %v matched; match(label=%v)",
				rc.GetName(), role.GetName(), labelsMessage)
			return trace.AccessDenied("access to cluster denied")
		}
	}

	// Check allow rules: label has to match in any role in the role set to be granted access.
	for _, role := range set {
		matchLabels, labelsMessage, err := MatchLabels(role.GetClusterLabels(types.Allow), rcLabels)
		debugf("Check access to role(%v) rc(%v, labels=%v) matchLabels=%v, msg=%v, err=%v allow=%v rcLabels=%v",
			role.GetName(), rc.GetName(), rcLabels, matchLabels, labelsMessage, err, role.GetClusterLabels(types.Allow), rcLabels)
		if err != nil {
			return trace.Wrap(err)
		}
		if matchLabels {
			return nil
		}
		if isDebugEnabled {
			deniedError := trace.AccessDenied("role=%v, match(label=%v)",
				role.GetName(), labelsMessage)
			errs = append(errs, deniedError)
		}
	}

	debugf("Access to cluster %v denied, no allow rule matched; %v", rc.GetName(), errs)
	return trace.AccessDenied("access to cluster denied")
}

// LockingMode returns the locking mode to apply with this RoleSet.
func (set RoleSet) LockingMode(defaultMode constants.LockingMode) constants.LockingMode {
	mode := defaultMode
	for _, role := range set {
		options := role.GetOptions()
		if options.Lock == constants.LockingModeStrict {
			return constants.LockingModeStrict
		}
		if options.Lock != "" {
			mode = options.Lock
		}
	}
	return mode
}

// SessionRecordingMode returns the recording mode for a specific service.
func (set RoleSet) SessionRecordingMode(service constants.SessionRecordingService) constants.SessionRecordingMode {
	defaultValue := constants.SessionRecordingModeBestEffort
	useDefault := true

	for _, role := range set {
		recordSession := role.GetOptions().RecordSession

		// If one of the default values is "strict", set it as the value.
		if recordSession.Default == constants.SessionRecordingModeStrict {
			defaultValue = constants.SessionRecordingModeStrict
		}

		var roleMode constants.SessionRecordingMode
		switch service {
		case constants.SessionRecordingServiceSSH:
			roleMode = recordSession.SSH
		}

		switch roleMode {
		case constants.SessionRecordingModeStrict:
			// Early return as "strict" since it is the strictest value.
			return constants.SessionRecordingModeStrict
		case constants.SessionRecordingModeBestEffort:
			useDefault = false
		}
	}

	// Return the strictest default value.
	if useDefault {
		return defaultValue
	}

	return constants.SessionRecordingModeBestEffort
}

// RoleMatcher defines an interface for a generic role matcher.
type RoleMatcher interface {
	Match(types.Role, types.RoleConditionType) (bool, error)
}

// RoleMatchers defines a list of matchers.
type RoleMatchers []RoleMatcher

// MatchAll returns true if all matchers in the set match.
func (m RoleMatchers) MatchAll(role types.Role, condition types.RoleConditionType) (bool, error) {
	for _, matcher := range m {
		match, err := matcher.Match(role, condition)
		if err != nil {
			return false, trace.Wrap(err)
		}
		if !match {
			return false, nil
		}
	}
	return true, nil
}

// MatchAny returns true if at least one of the matchers in the set matches.
//
// If the result is true, returns matcher that matched.
func (m RoleMatchers) MatchAny(role types.Role, condition types.RoleConditionType) (bool, RoleMatcher, error) {
	for _, matcher := range m {
		match, err := matcher.Match(role, condition)
		if err != nil {
			return false, nil, trace.Wrap(err)
		}
		if match {
			return true, matcher, nil
		}
	}
	return false, nil, nil
}

type loginMatcher struct {
	login string
}

// NewLoginMatcher creates a RoleMatcher that checks whether the role's logins
// match the specified condition.
func NewLoginMatcher(login string) RoleMatcher {
	return &loginMatcher{login: login}
}

// Match matches a login against a role.
func (l *loginMatcher) Match(role types.Role, typ types.RoleConditionType) (bool, error) {
	logins := role.GetLogins(typ)
	for _, login := range logins {
		if l.login == login {
			return true, nil
		}
	}
	return false, nil
}

// AccessCheckable is the subset of types.Resource required for the RBAC checks.
type AccessCheckable interface {
	GetKind() string
	GetName() string
	GetMetadata() types.Metadata
	GetAllLabels() map[string]string
}

// rbacDebugLogger creates a debug logger for Teleport's RBAC component.
// It also returns a flag indicating whether debug logging is enabled,
// allowing the RBAC system to generate more verbose errors in debug mode.
func rbacDebugLogger() (debugEnabled bool, debugf func(format string, args ...interface{})) {
	isDebugEnabled := log.IsLevelEnabled(log.DebugLevel)
	log := log.WithField(trace.Component, teleport.ComponentRBAC)
	return isDebugEnabled, log.Debugf
}

// checkAccess checks if this role set has access to a particular resource,
// optionally matching the resource's labels.
func (set RoleSet) checkAccess(r AccessCheckable, mfa AccessMFAParams, matchers ...RoleMatcher) error {
	// Note: logging in this function only happens in debug mode. This is because
	// adding logging to this function (which is called on every resource returned
	// by the backend) can slow down this function by 50x for large clusters!
	isDebugEnabled, debugf := rbacDebugLogger()

	if mfa.AlwaysRequired && !mfa.Verified {
		debugf("Access to %v %q denied, cluster requires per-session MFA", r.GetKind(), r.GetName())
		return ErrSessionMFARequired
	}

	namespace := types.ProcessNamespace(r.GetMetadata().Namespace)
	allLabels := r.GetAllLabels()

	// Additional message depending on kind of resource
	// so there's more context on why the user might not have access.
	additionalDeniedMessage := ""

	var getRoleLabels func(types.Role, types.RoleConditionType) types.Labels
	switch r.GetKind() {
	case types.KindNode:
		getRoleLabels = types.Role.GetNodeLabels
		additionalDeniedMessage = "Confirm SSH login."
	default:
		return trace.BadParameter("cannot match labels for kind %v", r.GetKind())
	}

	// Check deny rules.
	for _, role := range set {
		matchNamespace, namespaceMessage := MatchNamespace(role.GetNamespaces(types.Deny), namespace)
		if !matchNamespace {
			continue
		}

		matchLabels, labelsMessage, err := MatchLabels(getRoleLabels(role, types.Deny), allLabels)
		if err != nil {
			return trace.Wrap(err)
		}
		if matchLabels {
			debugf("Access to %v %q denied, deny rule in role %q matched; match(namespace=%v, label=%v)",
				r.GetKind(), r.GetName(), role.GetName(), namespaceMessage, labelsMessage)
			return trace.AccessDenied("access to %v denied. User does not have permissions. %v",
				r.GetKind(), additionalDeniedMessage)
		}

		// Deny rules are greedy on purpose. They will always match if
		// at least one of the matchers returns true.
		matchMatchers, matchersMessage, err := RoleMatchers(matchers).MatchAny(role, types.Deny)
		if err != nil {
			return trace.Wrap(err)
		}
		if matchMatchers {
			debugf("Access to %v %q denied, deny rule in role %q matched; match(matcher=%v)",
				r.GetKind(), r.GetName(), role.GetName(), matchersMessage)
			return trace.AccessDenied("access to %v denied. User does not have permissions. %v",
				r.GetKind(), additionalDeniedMessage)
		}
	}

	var errs []error
	allowed := false
	// Check allow rules.
	for _, role := range set {
		matchNamespace, namespaceMessage := MatchNamespace(role.GetNamespaces(types.Allow), namespace)
		if !matchNamespace {
			if isDebugEnabled {
				errs = append(errs, trace.AccessDenied("role=%v, match(namespace=%v)",
					role.GetName(), namespaceMessage))
			}
			continue
		}

		matchLabels, labelsMessage, err := MatchLabels(getRoleLabels(role, types.Allow), allLabels)
		if err != nil {
			return trace.Wrap(err)
		}
		if !matchLabels {
			if isDebugEnabled {
				errs = append(errs, trace.AccessDenied("role=%v, match(label=%v)",
					role.GetName(), labelsMessage))
			}
			continue
		}

		// Allow rules are not greedy. They will match only if all of the
		// matchers return true.
		matchMatchers, err := RoleMatchers(matchers).MatchAll(role, types.Allow)
		if err != nil {
			return trace.Wrap(err)
		}
		if !matchMatchers {
			if isDebugEnabled {
				errs = append(errs, fmt.Errorf("role=%v, match(matchers=%v)",
					role.GetName(), err))
			}
			continue
		}

		// if we've reached this point, namespace, labels, and matchers all match.
		// if MFA is verified, we're done.
		if mfa.Verified {
			return nil
		}
		// if MFA is not verified and we require session MFA, deny access
		if role.GetOptions().RequireSessionMFA {
			debugf("Access to %v %q denied, role %q requires per-session MFA",
				r.GetKind(), r.GetName(), role.GetName())
			return ErrSessionMFARequired
		}

		// Check all remaining roles, even if we found a match.
		// RequireSessionMFA should be enforced when at least one role has
		// it.
		allowed = true
		debugf("Access to %v %q granted, allow rule in role %q matched.",
			r.GetKind(), r.GetName(), role.GetName())
	}

	if allowed {
		return nil
	}

	debugf("Access to %v %q denied, no allow rule matched; %v", r.GetKind(), r.GetName(), errs)
	return trace.AccessDenied("access to %v denied. User does not have permissions. %v",
		r.GetKind(), additionalDeniedMessage)
}

// CanPortForward returns true if a role in the RoleSet allows port forwarding.
func (set RoleSet) CanPortForward() bool {
	for _, role := range set {
		if types.BoolDefaultTrue(role.GetOptions().PortForwarding) {
			return true
		}
	}
	return false
}

// PermitX11Forwarding returns true if this RoleSet allows X11 Forwarding.
func (set RoleSet) PermitX11Forwarding() bool {
	for _, role := range set {
		if role.GetOptions().PermitX11Forwarding.Value() {
			return true
		}
	}
	return false
}

// CanCopyFiles returns true if the role set has enabled remote file
// operations via SCP or SFTP. Remote file operations are disabled if
// one or more of the roles in the set has disabled it.
func (set RoleSet) CanCopyFiles() bool {
	for _, role := range set {
		if !types.BoolDefaultTrue(role.GetOptions().SSHFileCopy) {
			return false
		}
	}
	return true
}

// EnhancedRecordingSet returns the set of enhanced session recording
// events to capture for thi role set.
func (set RoleSet) EnhancedRecordingSet() map[string]bool {
	m := make(map[string]bool)

	// Loop over all roles and create a set of all options.
	for _, role := range set {
		for _, opt := range role.GetOptions().BPF {
			m[opt] = true
		}
	}

	return m
}

// HostUsers returns host user information matching a server or nil if
// a role disallows host user creation
func (set RoleSet) HostUsers(s types.Server) (*HostUsersInfo, error) {
	groups := make(map[string]struct{})
	sudoers := make(map[string]struct{})
	serverLabels := s.GetAllLabels()
	for _, role := range set {
		result, _, err := MatchLabels(role.GetNodeLabels(types.Allow), serverLabels)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		// skip nodes that dont have matching labels
		if !result {
			continue
		}
		createHostUser := role.GetOptions().CreateHostUser
		// if any of the matching roles do not enable create host
		// user, the user should not be allowed on
		if createHostUser == nil || !createHostUser.Value {
			return nil, trace.AccessDenied("user is not allowed to create host users")
		}
		for _, group := range role.GetHostGroups(types.Allow) {
			groups[group] = struct{}{}
		}
		for _, sudoer := range role.GetHostSudoers(types.Allow) {
			sudoers[sudoer] = struct{}{}
		}
	}
	for _, role := range set {
		result, _, err := MatchLabels(role.GetNodeLabels(types.Deny), serverLabels)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		if !result {
			continue
		}
		for _, group := range role.GetHostGroups(types.Deny) {
			delete(groups, group)
		}
		for _, sudoer := range role.GetHostSudoers(types.Deny) {
			if sudoer == "*" {
				sudoers = nil
				break
			}
			delete(sudoers, sudoer)
		}
	}

	return &HostUsersInfo{
		Groups:  utils.StringsSliceFromSet(groups),
		Sudoers: utils.StringsSliceFromSet(sudoers),
	}, nil
}

// CheckAgentForward checks if the role can request to forward the SSH agent
// for this user.
func (set RoleSet) CheckAgentForward(login string) error {
	// check if we have permission to login and forward agent. we don't check
	// for deny rules because if you can't forward an agent if you can't login
	// in the first place.
	for _, role := range set {
		for _, l := range role.GetLogins(types.Allow) {
			if role.GetOptions().ForwardAgent.Value() && l == login {
				return nil
			}
		}
	}
	return trace.AccessDenied("%v can not forward agent for %v", set, login)
}

func (set RoleSet) String() string {
	if len(set) == 0 {
		return "user without assigned roles"
	}
	roleNames := make([]string, len(set))
	for i, role := range set {
		roleNames[i] = role.GetName()
	}
	return fmt.Sprintf("roles %v", strings.Join(roleNames, ","))
}

// AccessMFAParams contains MFA-related parameters for methods that check access.
type AccessMFAParams struct {
	// AlwaysRequired is set when MFA is required for all sessions, regardless
	// of per-role options.
	AlwaysRequired bool
	// Verified is set when MFA has been verified by the caller.
	Verified bool
}

// SortedRoles sorts roles by name
type SortedRoles []types.Role

// Len returns length of a role list
func (s SortedRoles) Len() int {
	return len(s)
}

// Less compares roles by name
func (s SortedRoles) Less(i, j int) bool {
	return s[i].GetName() < s[j].GetName()
}

// Swap swaps two roles in a list
func (s SortedRoles) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// UnmarshalRole unmarshals the Role resource from JSON.
func UnmarshalRole(bytes []byte, opts ...MarshalOption) (types.Role, error) {
	var h types.ResourceHeader
	err := json.Unmarshal(bytes, &h)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	cfg, err := CollectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	switch h.Version {
	case types.V5:
		fallthrough
	case types.V4:
		// V4 roles are identical to V3 except for their defaults
		fallthrough
	case types.V3:
		var role types.RoleV5
		if err := utils.FastUnmarshal(bytes, &role); err != nil {
			return nil, trace.BadParameter(err.Error())
		}

		if err := ValidateRole(&role); err != nil {
			return nil, trace.Wrap(err)
		}

		if cfg.ID != 0 {
			role.SetResourceID(cfg.ID)
		}
		if !cfg.Expires.IsZero() {
			role.SetExpiry(cfg.Expires)
		}
		return &role, nil
	}

	return nil, trace.BadParameter("role version %q is not supported", h.Version)
}

// MarshalRole marshals the Role resource to JSON.
func MarshalRole(role types.Role, opts ...MarshalOption) ([]byte, error) {
	if err := ValidateRole(role); err != nil {
		return nil, trace.Wrap(err)
	}

	cfg, err := CollectOptions(opts)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	switch role := role.(type) {
	case *types.RoleV5:
		if !cfg.PreserveResourceID {
			// avoid modifying the original object
			// to prevent unexpected data races
			copy := *role
			copy.SetResourceID(0)
			role = &copy
		}
		return utils.FastMarshal(role)
	default:
		return nil, trace.BadParameter("unrecognized role version %T", role)
	}
}
