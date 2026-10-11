package attach

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// AttachUprobe attaches prog to a symbol of a userspace executable.
// When Ret is set, it attaches a uretprobe instead of a uprobe.
func (spec AttachmentSpec) AttachUprobe(prog *ebpf.Program) (link.Link, error) {
	ex, err := link.OpenExecutable(spec.Hook1)
	if err != nil {
		return nil, fmt.Errorf("opening executable %s: %w", spec.Hook1, err)
	}

	var l link.Link
	if spec.Ret {
		l, err = ex.Uretprobe(spec.Hook2, prog, nil)
	} else {
		l, err = ex.Uprobe(spec.Hook2, prog, nil)
	}
	if err != nil {
		return nil, fmt.Errorf("attaching %s: %w", spec, err)
	}
	return l, nil
}

// AttachTracepoint attaches prog to a classic tracepoint.
// Hook1 is the category, Hook2 the name.
func (spec AttachmentSpec) AttachTracepoint(prog *ebpf.Program) (link.Link, error) {
	l, err := link.Tracepoint(spec.Hook1, spec.Hook2, prog, nil)
	if err != nil {
		return nil, fmt.Errorf("attaching tracepoint %s: %w", spec, err)
	}
	return l, nil
}

// AttachBTFTracepoint attaches prog to a BTF tracepoint (tp_btf).
// Hook1 is the full tracepoint name.
func (spec AttachmentSpec) AttachBTFTracepoint(prog *ebpf.Program) (link.Link, error) {
	l, err := link.AttachTracing(link.TracingOptions{
		Program:    prog,
		AttachType: ebpf.AttachTraceRawTp,
	})
	if err != nil {
		return nil, fmt.Errorf("attaching tp_btf %s: %w", spec, err)
	}
	return l, nil
}

// AttachFentry attaches a BTF tracing program to the entry of the kernel
// function named in Hook1.
func (spec AttachmentSpec) AttachFentry(prog *ebpf.Program) (link.Link, error) {
	l, err := link.AttachTracing(link.TracingOptions{
		Program:    prog,
		AttachType: ebpf.AttachTraceFEntry,
	})
	if err != nil {
		return nil, fmt.Errorf("attaching fentry %s: %w", spec, err)
	}
	return l, nil
}

// AttachFexit attaches a BTF tracing program to the exit of the kernel
// function named in Hook1.
func (spec AttachmentSpec) AttachFexit(prog *ebpf.Program) (link.Link, error) {
	l, err := link.AttachTracing(link.TracingOptions{
		Program:    prog,
		AttachType: ebpf.AttachTraceFExit,
	})
	if err != nil {
		return nil, fmt.Errorf("attaching fexit %s: %w", spec, err)
	}
	return l, nil
}

// AttachLSM attaches prog to an LSM hook. Hook1 is the hook name.
func (spec AttachmentSpec) AttachLSM(prog *ebpf.Program) (link.Link, error) {
	l, err := link.AttachLSM(link.LSMOptions{Program: prog})
	if err != nil {
		return nil, fmt.Errorf("attaching lsm %s: %w", spec, err)
	}
	return l, nil
}

// AttachKprobe attaches prog to a kernel function.
// When Ret is set, it attaches a kretprobe instead of a kprobe.
func (spec AttachmentSpec) AttachKprobe(prog *ebpf.Program) (link.Link, error) {
	var l link.Link
	var err error
	if spec.Ret {
		l, err = link.Kretprobe(spec.Hook1, prog, nil)
	} else {
		l, err = link.Kprobe(spec.Hook1, prog, nil)
	}
	if err != nil {
		return nil, fmt.Errorf("attaching kprobe %s: %w", spec, err)
	}
	return l, nil
}

// AttachXDP attaches prog as an XDP program on the interface named in Hook1.
func (spec AttachmentSpec) AttachXDP(prog *ebpf.Program) (link.Link, error) {
	iface, err := net.InterfaceByName(spec.Hook1)
	if err != nil {
		return nil, fmt.Errorf("looking up interface %s: %w", spec.Hook1, err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
	})
	if err != nil {
		return nil, fmt.Errorf("attaching xdp on %s: %w", spec.Hook1, err)
	}
	return l, nil
}

// AttachTC attaches prog as a TCX program on the interface named in Hook1.
// Direction selects ingress or egress (default: egress).
func (spec AttachmentSpec) AttachTC(prog *ebpf.Program) (link.Link, error) {
	iface, err := net.InterfaceByName(spec.Hook1)
	if err != nil {
		return nil, fmt.Errorf("looking up interface %s: %w", spec.Hook1, err)
	}

	attach := ebpf.AttachTCXEgress
	if spec.Direction == Ingress {
		attach = ebpf.AttachTCXIngress
	}

	l, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   prog,
		Attach:    attach,
	})
	if err != nil {
		return nil, fmt.Errorf("attaching tc on %s (%s): %w", spec.Hook1, attach, err)
	}
	return l, nil
}
