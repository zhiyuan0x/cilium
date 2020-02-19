package connector

import (
	"fmt"
	"runtime"
	"unsafe"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// TODO: We cannot include bpf package here due to CGO_ENABLED=0,
// but we should refactor common bits into a pure golang package.

type bpfAttrProg struct {
	ProgType    uint32
	InsnCnt     uint32
	Insns       uintptr
	License     uintptr
	LogLevel    uint32
	LogSize     uint32
	LogBuf      uintptr
	KernVersion uint32
	Flags       uint32
	Name        [16]byte
}

func loadEntryProg(mapFd int, key uint8) (int, error) {
	tmp := (*[4]byte)(unsafe.Pointer(&mapFd))
	insns := []byte{
		// BPF_LD | BPF_IMM | BPF_DW
		0x18, 0x12, 0x00, 0x00, tmp[0], tmp[1], tmp[2], tmp[3],
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// BPF_ALU64 | BPF_K | BPF_MOVE
		0xb7, 0x03, 0x00, 0x00, byte(key), 0x00, 0x00, 0x00,
		// BPF_JMP | BPF_K | BPF_CALL
		0x85, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00,
		// BPF_ALU64 | BPF_MOVE
		0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// BPF_JMP | BPF_K | BPF_CALL
		0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	license := []byte{'A', 'S', 'L', '2', '\x00'}
	bpfAttr := bpfAttrProg{
		ProgType: 3,
		InsnCnt:  uint32(len(insns) / 8),
		Insns:    uintptr(unsafe.Pointer(&insns[0])),
		License:  uintptr(unsafe.Pointer(&license[0])),
	}
	fd, _, errno := unix.Syscall(unix.SYS_BPF, 5, /* BPF_PROG_LOAD */
		uintptr(unsafe.Pointer(&bpfAttr)),
		unsafe.Sizeof(bpfAttr))
	runtime.KeepAlive(&insns)
	runtime.KeepAlive(&license)
	runtime.KeepAlive(&bpfAttr)
	if errno != 0 {
		return 0, errno
	}
	return int(fd), nil
}

type bpfAttrMap struct {
	MapType    uint32
	SizeKey    uint32
	SizeValue  uint32
	MaxEntries uint32
	Flags      uint32
}

type bpfMapInfo struct {
	MapType    uint32
	MapID      uint32
	SizeKey    uint32
	SizeValue  uint32
	MaxEntries uint32
	Flags      uint32
}

type bpfAttrObjInfo struct {
	Fd      uint32
	InfoLen uint32
	Info    uint64
}

func createTailCallMap() (int, int, error) {
	bpfAttr := bpfAttrMap{
		MapType:    3,
		SizeKey:    4,
		SizeValue:  4,
		MaxEntries: 2,
		Flags:      0,
	}
	fd, _, errno := unix.Syscall(unix.SYS_BPF, 0, /* BPF_MAP_CREATE */
		uintptr(unsafe.Pointer(&bpfAttr)),
		unsafe.Sizeof(bpfAttr))
	runtime.KeepAlive(&bpfAttr)
	if int(fd) < 0 || errno != 0 {
		return 0, 0, errno
	}

	info := bpfMapInfo{}
	bpfAttrInfo := bpfAttrObjInfo{
		Fd:      uint32(fd),
		InfoLen: uint32(unsafe.Sizeof(info)),
		Info:    uint64(uintptr(unsafe.Pointer(&info))),
	}
	bpfAttr2 := struct {
		info bpfAttrObjInfo
	}{
		info: bpfAttrInfo,
	}
	ret, _, errno := unix.Syscall(unix.SYS_BPF, 15, /* BPF_OBJ_GET_INFO_BY_FD */
		uintptr(unsafe.Pointer(&bpfAttr2)),
		unsafe.Sizeof(bpfAttr2))
	runtime.KeepAlive(&info)
	runtime.KeepAlive(&bpfAttr2)
	if ret != 0 || errno != 0 {
		unix.Close(int(fd))
		return 0, 0, errno
	}

	return int(fd), int(info.MapID), nil
}

// SetupInterfaceInRemoteNsWithBPF creates a tail call map, attaches BPF programs to
// the netdevice inside the target netns. egress path jumps into the tail call map
// index 0, ingress path jumps into index 1.
//
// NB: Do not close the returned mapFd before it has been pinned. Otherwise,
// the map will be destroyed.
func SetupInterfaceInRemoteNsWithBPF(netNs ns.NetNS, ifName string, ingress bool, egress bool) (int, int, error) {
	rl := unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}

	err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &rl)
	if err != nil {
		return 0, 0, fmt.Errorf("Unable to increase rlimit: %s", err)
	}

	mapFd, mapId, err := createTailCallMap()
	if err != nil {
		return 0, 0, fmt.Errorf("failed to create root BPF map for %q: %s", ifName, err)
	}

	err = netNs.Do(func(_ ns.NetNS) error {
		var err error

		link, err := netlink.LinkByName(ifName)
		if err != nil {
			return fmt.Errorf("failed to lookup device %q: %s", ifName, err)
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
			return fmt.Errorf("failed to create clsact qdisc on %q: %s", ifName, err)
		}

		if egress {
			progFd, err := loadEntryProg(mapFd, 0)
			if err != nil {
				return fmt.Errorf("failed to load egress root BPF prog for %q: %s", ifName, err)
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
				Fd:           progFd,
				Name:         "polEntry",
				DirectAction: true,
			}
			if err = netlink.FilterAdd(filter); err != nil {
				unix.Close(progFd)
				return fmt.Errorf("failed to create egress cls_bpf filter on %q: %s", ifName, err)
			}
		}

		if ingress {
			progFd, err := loadEntryProg(mapFd, 1)
			if err != nil {
				return fmt.Errorf("failed to load ingress root eBPF prog for %q: %s", ifName, err)
			}

			filterAttrs := netlink.FilterAttrs{
				LinkIndex: link.Attrs().Index,
				Parent:    netlink.HANDLE_MIN_INGRESS,
				Handle:    netlink.MakeHandle(0, 1),
				Protocol:  unix.ETH_P_ALL,
				Priority:  1,
			}
			filter := &netlink.BpfFilter{
				FilterAttrs:  filterAttrs,
				Fd:           progFd,
				Name:         "ingressPolEntry",
				DirectAction: true,
			}
			if err = netlink.FilterAdd(filter); err != nil {
				unix.Close(progFd)
				return fmt.Errorf("failed to create ingress cls_bpf ingress filter on %q: %s", ifName, err)
			}
		}

		return nil
	})
	if err != nil {
		unix.Close(mapFd)
		return 0, 0, err
	}
	return mapFd, mapId, nil
}
