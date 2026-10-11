package attach

import (
	"strings"
	"testing"
)

func TestResolveAttachmentWithEmptyArgLeavesSpec(t *testing.T) {
	spec := AttachmentSpec{Type: "kprobe", Hook1: "sys_enter_write"}

	got, err := spec.ResolveAttachmentWith("")
	if err != nil {
		t.Fatalf("ResolveAttachmentWith(\"\") returned error: %v", err)
	}
	if got != spec {
		t.Errorf("empty argument should not change the spec: got %+v", got)
	}
}

func TestResolveAttachmentWithHook1Only(t *testing.T) {
	spec := AttachmentSpec{Type: "kprobe", Hook1: "default"}

	got, err := spec.ResolveAttachmentWith("sys_enter_read")
	if err != nil {
		t.Fatalf("ResolveAttachmentWith returned error: %v", err)
	}
	if got.Hook1 != "sys_enter_read" {
		t.Errorf("Hook1 = %q, want %q", got.Hook1, "sys_enter_read")
	}
	if got.Hook2 != "" {
		t.Errorf("Hook2 should be empty, got %q", got.Hook2)
	}
}

func TestResolveAttachmentWithHook1Hook2(t *testing.T) {
	spec := AttachmentSpec{Type: "tracepoint", Hook1: "c", Hook2: "n"}

	got, err := spec.ResolveAttachmentWith("sched:sched_switch")
	if err != nil {
		t.Fatalf("ResolveAttachmentWith returned error: %v", err)
	}
	if got.Hook1 != "sched" || got.Hook2 != "sched_switch" {
		t.Errorf("got Hook1=%q Hook2=%q, want sched/sched_switch", got.Hook1, got.Hook2)
	}
}

func TestResolveAttachmentWithColonInHook2(t *testing.T) {
	// A second colon belongs to Hook2, not a parse error.
	spec := AttachmentSpec{Type: "uprobe"}

	got, err := spec.ResolveAttachmentWith("/bin/ls:main:extra")
	if err != nil {
		t.Fatalf("ResolveAttachmentWith returned error: %v", err)
	}
	if got.Hook1 != "/bin/ls" || got.Hook2 != "main:extra" {
		t.Errorf("got Hook1=%q Hook2=%q", got.Hook1, got.Hook2)
	}
}

func TestResolveAttachmentWithRejectsBareOverride(t *testing.T) {
	// Overriding a spec that has a Hook2 with a bare hook1 must fail.
	spec := AttachmentSpec{Type: "tracepoint", Hook1: "c", Hook2: "n"}

	_, err := spec.ResolveAttachmentWith("bare")
	if err == nil {
		t.Fatal("ResolveAttachmentWith(bare) should return an error when Hook2 is set")
	}
	if !strings.Contains(err.Error(), "invalid attachment format") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestResolveAttachmentWithDoesNotMutateReceiver(t *testing.T) {
	spec := AttachmentSpec{Type: "kprobe", Hook1: "original"}

	_, _ = spec.ResolveAttachmentWith("overridden")
	if spec.Hook1 != "original" {
		t.Errorf("receiver was mutated: Hook1 = %q, want %q", spec.Hook1, "original")
	}
}

func TestAttachmentSpecString(t *testing.T) {
	cases := []struct {
		spec AttachmentSpec
		want string
	}{
		{AttachmentSpec{Hook1: "a"}, "a"},
		{AttachmentSpec{Hook1: "a", Hook2: "b"}, "a:b"},
	}
	for _, c := range cases {
		if got := c.spec.String(); got != c.want {
			t.Errorf("String() = %q, want %q", got, c.want)
		}
	}
}
