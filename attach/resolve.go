package attach

import (
	"fmt"
	"os"
	"strings"
)

// ResolveAttachment overrides the spec's hooks with the first command-line
// argument, which must have the form "hook1" or "hook1:hook2".
//
// Deprecated: reading os.Args is a side effect that makes the result
// impossible to test and to reason about. Call ResolveAttachmentWith with an
// explicit argument instead (typically os.Args[1], checked by the caller).
func (spec AttachmentSpec) ResolveAttachment() (AttachmentSpec, error) {
	if len(os.Args) > 1 {
		return spec.ResolveAttachmentWith(os.Args[1])
	}
	return spec, nil
}

// ResolveAttachmentWith returns a copy of the spec overridden with the
// argument, which must have the form "hook1" or "hook1:hook2". An empty
// argument leaves the spec unchanged.
func (spec AttachmentSpec) ResolveAttachmentWith(arg string) (AttachmentSpec, error) {
	if arg == "" {
		return spec, nil
	}

	parts := strings.SplitN(arg, ":", 2)
	if len(parts) != 2 && spec.Hook2 != "" {
		return AttachmentSpec{}, fmt.Errorf("invalid attachment format %q: expected %q or %q", arg, "hook1", "hook1:hook2")
	}
	spec.Hook1 = parts[0]
	if len(parts) > 1 {
		spec.Hook2 = parts[1]
	}

	return spec, nil
}

// String renders the attachment as "hook1:hook2" (or "hook1").
func (spec AttachmentSpec) String() string {
	if spec.Hook2 != "" {
		return fmt.Sprintf("%s:%s", spec.Hook1, spec.Hook2)
	}
	return spec.Hook1
}
