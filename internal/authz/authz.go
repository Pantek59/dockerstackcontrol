// Package authz evaluates permission rules against a configuration snapshot.
//
// Authorization is deny-by-default: a user may act on a stack only through a
// rule whose subjects match the user (username equal to an entry in users, or
// any of the user's groups equal to an entry in groups) and whose stack list
// contains the stack (or "*"). Matching rules are unioned. All functions take
// an immutable *config.Config snapshot and are safe for concurrent use.
package authz

import (
	"github.com/Pantek59/dockerstackcontrol/internal/config"
)

// subjectsMatch reports whether the rule's subject set contains the user.
// Matching is exact and case-sensitive: usernames and group names are
// compared as-is against the identity provider's claims.
func subjectsMatch(ss config.SubjectSet, user string, groups []string) bool {
	set := make(map[string]struct{}, len(ss.Users))
	for _, u := range ss.Users {
		set[u] = struct{}{}
	}
	if _, ok := set[user]; ok {
		return true
	}
	if len(ss.Groups) > 0 && len(groups) > 0 {
		gset := make(map[string]struct{}, len(groups))
		for _, g := range groups {
			gset[g] = struct{}{}
		}
		for _, g := range ss.Groups {
			if _, ok := gset[g]; ok {
				return true
			}
		}
	}
	return false
}

// stackMatches reports whether the rule's stack list covers name.
// "*" covers every stack that is declared in the configuration.
func stackMatches(ruleStacks []string, name string) bool {
	for _, s := range ruleStacks {
		if s == "*" || s == name {
			return true
		}
	}
	return false
}

// effectiveActions returns the set of actions the user may perform on the
// stack name, empty when no rule matches. Actions outside the known enum are
// dropped. Unknown stack names always yield an empty set: "*" in a rule means
// all configured stacks, never names outside the configuration.
func effectiveActions(c *config.Config, user string, groups []string, name string) map[string]struct{} {
	if _, ok := c.Stack(name); !ok {
		return nil
	}
	set := make(map[string]struct{})
	for _, rule := range c.Rules {
		if !subjectsMatch(rule.Subjects, user, groups) {
			continue
		}
		if !stackMatches(rule.Stacks, name) {
			continue
		}
		for _, a := range rule.Actions {
			if config.ValidAction(a) {
				set[a] = struct{}{}
			}
		}
	}
	return set
}

// AllowedActions returns the actions the user may perform on the named stack,
// in canonical order, deduplicated. The result is an empty (non-nil) slice
// when the user has no permission. Unknown stacks yield an empty slice.
func AllowedActions(c *config.Config, user string, groups []string, name string) []string {
	set := effectiveActions(c, user, groups, name)
	out := make([]string, 0, len(set))
	for _, a := range config.CanonicalActions {
		if _, ok := set[a]; ok {
			out = append(out, a)
		}
	}
	return out
}

// IsVisible reports whether the user may see the stack at all: they have at
// least one allowed action on a configured stack.
func IsVisible(c *config.Config, user string, groups []string, name string) bool {
	return len(effectiveActions(c, user, groups, name)) > 0
}

// VisibleStacks returns the stacks the user may see, in configuration order.
func VisibleStacks(c *config.Config, user string, groups []string) []config.Stack {
	out := make([]config.Stack, 0, len(c.Stacks))
	for _, s := range c.Stacks {
		if IsVisible(c, user, groups, s.Name) {
			out = append(out, s)
		}
	}
	return out
}

// Can reports whether the user may perform the named action on the named
// stack. Unknown stacks and actions outside the enum are always false.
func Can(c *config.Config, user string, groups []string, name, action string) bool {
	if !config.ValidAction(action) {
		return false
	}
	_, ok := effectiveActions(c, user, groups, name)[action]
	return ok
}
