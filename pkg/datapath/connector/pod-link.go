package connector

import (
	"fmt"

	"github.com/cilium/cilium/pkg/datapath/link"

	"github.com/cilium/ebpf"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"

	"golang.org/x/sys/unix"
)

const (
	// TailCallMapIndexEngress is the map index of 'from-endpoint' program
	TailCallMapIndexEngress = 0
	// TailCallMapIndexIngress is the map index of 'to-endpoint' bpf program
	TailCallMapIndexIngress = 1
)

// SetupNicInRemoteNs renames the netdev in netns, creates two direction bpf
// programs and a tail-call map. The egress bpf calls the map with index
// TailCallMapIndexEngress(0), ingress bpf calls the map with index
// TailCallMapIndexIngress(1).
//
// The tail call map doestn't has actual programs now. These programs will be
// loaded after the datapath loader will call graftDatapath().
//
// NB: Do not close the returned map before it has been pinned. Otherwise,
// the map will be destroyed.
func SetupNicInRemoteNs(netNs ns.NetNS, srcIfName, dstIfName string, egress bool, ingress bool) (*ebpf.Map, error) {
	rl := unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}

	err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &rl)
	if err != nil {
		return nil, fmt.Errorf("unable to increase rlimit: %w", err)
	}

	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.ProgramArray,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 2,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create root BPF map for %q: %w", dstIfName, err)
	}

	err = netNs.Do(func(_ ns.NetNS) error {
		var err error

		if srcIfName != dstIfName {
			err = link.Rename(srcIfName, dstIfName)
			if err != nil {
				return fmt.Errorf("failed to rename device from %q to %q: %w", srcIfName, dstIfName, err)
			}
		}

		link, err := netlink.LinkByName(dstIfName)
		if err != nil {
			return fmt.Errorf("failed to lookup device %q: %w", dstIfName, err)
		}

		qdiscAttrs := netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		}
		qdisc := &netlink.GenericQdisc{
			QdiscAttrs: qdiscAttrs,
			QdiscType:  "clsact",
		}
		if err = netlink.QdiscAdd(qdisc); err != nil {
			return fmt.Errorf("failed to create clsact qdisc on %q: %w", dstIfName, err)
		}

		if egress {
			prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
				Type:         ebpf.SchedCLS,
				Instructions: getEntryProgInstructions(m.FD(), TailCallMapIndexEngress),
				License:      "ASL2",
			})
			if err != nil {
				return fmt.Errorf("failed to load root BPF prog for %q: %w", dstIfName, err)
			}

			filterAttrs := netlink.FilterAttrs{
				LinkIndex: link.Attrs().Index,
				Parent:    netlink.HANDLE_MIN_EGRESS,
				Handle:    netlink.MakeHandle(0, 1),
				Protocol:  3,
				Priority:  1,
			}
			filter := &netlink.BpfFilter{
				FilterAttrs:  filterAttrs,
				Fd:           prog.FD(),
				Name:         "polEntry",
				DirectAction: true,
			}
			if err = netlink.FilterAdd(filter); err != nil {
				prog.Close()
				return fmt.Errorf("failed to create cls_bpf filter on %q: %w", dstIfName, err)
			}
		}

		if ingress {
			prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
				Type:         ebpf.SchedCLS,
				Instructions: getEntryProgInstructions(m.FD(), TailCallMapIndexIngress),
				License:      "ASL2",
			})
			if err != nil {
				return fmt.Errorf("failed to load root BPF prog for %q: %w", dstIfName, err)
			}

			filterAttrs := netlink.FilterAttrs{
				LinkIndex: link.Attrs().Index,
				Parent:    netlink.HANDLE_MIN_INGRESS,
				Handle:    netlink.MakeHandle(0, 1),
				Protocol:  3,
				Priority:  1,
			}
			filter := &netlink.BpfFilter{
				FilterAttrs:  filterAttrs,
				Fd:           prog.FD(),
				Name:         "ingressPolEntry",
				DirectAction: true,
			}
			if err = netlink.FilterAdd(filter); err != nil {
				prog.Close()
				return fmt.Errorf("failed to create ingress cls_bpf filter on %q: %w", dstIfName, err)
			}
		}

		return nil
	})
	if err != nil {
		m.Close()
		return nil, err
	}
	return m, nil
}
