package authz

import (
	"reflect"
	"testing"

	"github.com/Pantek59/dockerstackcontrol/internal/config"
)

// testConfig is a fixed configuration snapshot used by the table tests.
func testConfig() *config.Config {
	return &config.Config{
		Stacks: []config.Stack{
			{Name: "media", Label: "Media Server", Project: "media"},
			{Name: "nextcloud", Label: "Nextcloud", Project: "nextcloud"},
		},
		Rules: []config.Rule{
			{ // admins and alice: everything on everything
				Subjects: config.SubjectSet{Users: []string{"alice"}, Groups: []string{"admins"}},
				Stacks:   []string{"*"},
				Actions:  []string{"start", "stop", "restart"},
			},
			{ // file-backed actions for the editors group on media
				Subjects: config.SubjectSet{Groups: []string{"editors"}},
				Stacks:   []string{"media"},
				Actions:  []string{"pull", "up", "edit"},
			},
			{ // bob: restart only on media
				Subjects: config.SubjectSet{Users: []string{"bob"}},
				Stacks:   []string{"media"},
				Actions:  []string{"restart"},
			},
			{ // family group: stop on nextcloud
				Subjects: config.SubjectSet{Groups: []string{"family"}},
				Stacks:   []string{"nextcloud"},
				Actions:  []string{"stop"},
			},
			{ // bob additionally in group ops: start on media (union case)
				Subjects: config.SubjectSet{Groups: []string{"ops"}},
				Stacks:   []string{"media"},
				Actions:  []string{"start"},
			},
		},
	}
}

// fileActionsConfig grants only the file-backed actions on media, so the
// union/ordering can be checked in isolation.
func fileActionsConfig() *config.Config {
	return &config.Config{
		Stacks: []config.Stack{
			{Name: "media", Label: "Media Server", Project: "media"},
		},
		Rules: []config.Rule{{
			Subjects: config.SubjectSet{Groups: []string{"editors"}},
			Stacks:   []string{"media"},
			Actions:  []string{"pull", "up", "edit"},
		}},
	}
}

func TestAllowedActions(t *testing.T) {
	tests := []struct {
		name   string
		cfg    *config.Config
		user   string
		groups []string
		stack  string
		want   []string
	}{
		{
			name: "user match via users list",
			user: "alice", stack: "media",
			want: []string{"start", "stop", "restart"},
		},
		{
			name: "group match via groups list",
			user: "carol", groups: []string{"family"}, stack: "nextcloud",
			want: []string{"stop"},
		},
		{
			name: "wildcard stack covers all configured stacks",
			user: "alice", stack: "nextcloud",
			want: []string{"start", "stop", "restart"},
		},
		{
			name: "union of user rule and group rule",
			user: "bob", groups: []string{"ops"}, stack: "media",
			want: []string{"start", "restart"}, // canonical order, deduped
		},
		{
			name: "rule without group membership does not match",
			user: "bob", groups: []string{"nobody"}, stack: "media",
			want: []string{"restart"},
		},
		{
			name: "default deny for unknown user",
			user: "eve", stack: "media",
			want: []string{},
		},
		{
			name: "default deny with empty groups for group-only rule",
			user: "carol", groups: nil, stack: "nextcloud",
			want: []string{},
		},
		{
			name: "unknown stack is not covered by wildcard",
			user: "alice", groups: []string{"admins"}, stack: "ghost",
			want: []string{},
		},
		{
			name: "unknown action is never allowed",
			user: "alice", stack: "media",
			want: []string{"start", "stop", "restart"},
		},
		{
			name: "file-backed actions in canonical order",
			cfg:  fileActionsConfig(),
			user: "dana", groups: []string{"editors"}, stack: "media",
			want: []string{"pull", "up", "edit"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			if cfg == nil {
				cfg = testConfig()
			}
			got := AllowedActions(cfg, tc.user, tc.groups, tc.stack)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("AllowedActions(%q, %v, %q) = %v, want %v", tc.user, tc.groups, tc.stack, got, tc.want)
			}
		})
	}
}

func TestAllowedActionsSubsetValidation(t *testing.T) {
	// Config validation rejects actions outside the enum, but the pure
	// evaluator must still be defensive when handed arbitrary input.
	cfg := testConfig()
	cfg.Rules = []config.Rule{{
		Subjects: config.SubjectSet{Users: []string{"alice"}},
		Stacks:   []string{"*"},
		Actions:  []string{"start", "nuke", "STOP"},
	}}
	got := AllowedActions(cfg, "alice", nil, "media")
	want := []string{"start"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("AllowedActions = %v, want %v", got, want)
	}
	if Can(cfg, "alice", nil, "media", "nuke") {
		t.Error("Can() allowed unknown action")
	}
}

func TestCan(t *testing.T) {
	cfg := testConfig()
	if !Can(cfg, "alice", nil, "media", "restart") {
		t.Error("alice must be able to restart media")
	}
	if !Can(cfg, "bob", nil, "media", "restart") {
		t.Error("bob must be able to restart media")
	}
	if Can(cfg, "bob", nil, "media", "stop") {
		t.Error("bob must not be able to stop media")
	}
	if Can(cfg, "bob", nil, "nextcloud", "stop") {
		t.Error("bob must not be able to stop nextcloud")
	}
	if !Can(cfg, "carol", []string{"family"}, "nextcloud", "stop") {
		t.Error("carol:family must be able to stop nextcloud")
	}
	if Can(cfg, "carol", []string{"family"}, "nextcloud", "start") {
		t.Error("carol:family must not be able to start nextcloud")
	}
}

func TestIsVisible(t *testing.T) {
	cfg := testConfig()
	if !IsVisible(cfg, "bob", nil, "media") {
		t.Error("media should be visible to bob")
	}
	if IsVisible(cfg, "bob", nil, "nextcloud") {
		t.Error("nextcloud must be invisible to bob")
	}
	if IsVisible(cfg, "carol", []string{"family"}, "media") {
		t.Error("media must be invisible to carol:family")
	}
	if IsVisible(cfg, "alice", nil, "ghost") {
		t.Error("unknown stack must never be visible")
	}
}

func TestVisibleStacksOrder(t *testing.T) {
	cfg := testConfig()
	// bob sees exactly media, in configuration order.
	got := VisibleStacks(cfg, "bob", nil)
	if len(got) != 1 || got[0].Name != "media" {
		t.Errorf("VisibleStacks(bob) = %+v, want [media]", got)
	}

	// A user in family+ops sees nextcloud (stop) and media (start).
	got = VisibleStacks(cfg, "dave", []string{"family", "ops"})
	if len(got) != 2 || got[0].Name != "media" || got[1].Name != "nextcloud" {
		t.Errorf("VisibleStacks(dave) = %+v, want [media nextcloud] in config order", got)
	}

	// No rules at all: empty slice, not nil, and empty list rendering.
	emptyCfg := &config.Config{Stacks: cfg.Stacks}
	got = VisibleStacks(emptyCfg, "eve", nil)
	if got == nil || len(got) != 0 {
		t.Errorf("VisibleStacks(eve) = %v, want empty non-nil", got)
	}
}

func TestGroupMatchingIsCaseSensitive(t *testing.T) {
	if subjectsMatch(config.SubjectSet{Groups: []string{"Admins"}}, "x", []string{"admins"}) {
		t.Error("group matching must be exact")
	}
}

func TestUserWithNoGroupsNeverMatchesGroupRule(t *testing.T) {
	cfg := testConfig()
	if got := AllowedActions(cfg, "carol", nil, "nextcloud"); len(got) != 0 {
		t.Errorf("AllowedActions without groups = %v, want none", got)
	}
}

func TestConcurrentSnapshotUse(t *testing.T) {
	// The evaluator must not mutate anything: run parallel readers to catch
	// accidental races under -race.
	cfg := testConfig()
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 200; j++ {
				_ = AllowedActions(cfg, "alice", []string{"admins"}, "media")
				_ = VisibleStacks(cfg, "bob", nil)
				_ = Can(cfg, "eve", nil, "media", "stop")
			}
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
}
