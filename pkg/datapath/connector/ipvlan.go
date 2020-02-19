// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package connector

import (
	"fmt"
	"strings"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/datapath/link"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/containernetworking/plugins/pkg/ns"

	"github.com/vishvananda/netlink"
)

// setupIpvlanInRemoteNs renames device name and setups tc-bpf filter and tail call map.
func setupIpvlanInRemoteNs(netNs ns.NetNS, srcIfName, dstIfName string) (int, int, error) {
	if err := netNs.Do(func(ns.NetNS) error {
		if srcIfName != dstIfName {
			if err := link.Rename(srcIfName, dstIfName); err != nil {
				return fmt.Errorf("failed to rename device %s to %s: %s", srcIfName, dstIfName, err)
			}
		}
		return nil
	}); err != nil {
		return 0, 0, err
	}

	return SetupInterfaceInRemoteNsWithBPF(netNs, dstIfName, false, true)
}

// CreateIpvlanSlave creates an ipvlan slave in L3 based on the master device.
func CreateIpvlanSlave(id string, mtu, masterDev int, mode string, ep *models.EndpointChangeRequest) (*netlink.IPVlan, *netlink.Link, string, error) {
	if id == "" {
		return nil, nil, "", fmt.Errorf("invalid: empty ID")
	}

	tmpIfName := Endpoint2TempIfName(id)
	ipvlan, link, err := createIpvlanSlave(tmpIfName, mtu, masterDev, mode, ep)

	return ipvlan, link, tmpIfName, err
}

func createIpvlanSlave(lxcIfName string, mtu, masterDev int, mode string, ep *models.EndpointChangeRequest) (*netlink.IPVlan, *netlink.Link, error) {
	var (
		link       netlink.Link
		err        error
		ipvlanMode netlink.IPVlanMode
	)

	if masterDev == 0 {
		return nil, nil, fmt.Errorf("invalid: master device ifindex")
	}

	switch mode {
	case OperationModeL3:
		ipvlanMode = netlink.IPVLAN_MODE_L3
	case OperationModeL3S:
		ipvlanMode = netlink.IPVLAN_MODE_L3S
	default:
		return nil, nil, fmt.Errorf("invalid or unsupported ipvlan operation mode: %s", mode)
	}

	ipvlan := &netlink.IPVlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:        lxcIfName,
			ParentIndex: masterDev,
		},
		Mode: ipvlanMode,
	}

	if err = netlink.LinkAdd(ipvlan); err != nil {
		return nil, nil, fmt.Errorf("unable to create ipvlan slave device: %s", err)
	}

	master, err := netlink.LinkByIndex(masterDev)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to find master device: %s", err)
	}

	defer func() {
		if err != nil {
			if err = netlink.LinkDel(ipvlan); err != nil {
				log.WithError(err).WithField(logfields.Ipvlan, ipvlan.Name).Warn("failed to clean up ipvlan")
			}
		}
	}()

	log.WithField(logfields.Ipvlan, []string{lxcIfName}).Debug("Created ipvlan slave in L3 mode")

	err = DisableRpFilter(lxcIfName)
	if err != nil {
		return nil, nil, err
	}

	link, err = netlink.LinkByName(lxcIfName)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to lookup ipvlan slave just created: %s", err)
	}

	if err = netlink.LinkSetMTU(link, mtu); err != nil {
		return nil, nil, fmt.Errorf("unable to set MTU to %q: %s", lxcIfName, err)
	}

	ep.Mac = link.Attrs().HardwareAddr.String()
	ep.HostMac = master.Attrs().HardwareAddr.String()
	ep.InterfaceIndex = int64(link.Attrs().Index)
	ep.InterfaceName = link.Attrs().Name

	return ipvlan, &link, nil
}

// CreateAndSetupIpvlanSlave creates an ipvlan slave device for the given
// master device, moves it to the given network namespace, and finally
// initializes it (see setupIpvlanInRemoteNs).
func CreateAndSetupIpvlanSlave(id string, slaveIfName string, netNs ns.NetNS, mtu int, masterDev int, mode string, ep *models.EndpointChangeRequest) (int, error) {
	var tmpIfName string

	if id == "" {
		tmpIfName = Endpoint2TempRandIfName()
	} else {
		tmpIfName = Endpoint2TempIfName(id)
	}

	_, link, err := createIpvlanSlave(tmpIfName, mtu, masterDev, mode, ep)
	if err != nil {
		return 0, fmt.Errorf("createIpvlanSlave has failed: %s", err)
	}

	if err = netlink.LinkSetNsFd(*link, int(netNs.Fd())); err != nil {
		return 0, fmt.Errorf("unable to move ipvlan slave '%v' to netns: %s", link, err)
	}

	mapFD, mapID, err := setupIpvlanInRemoteNs(netNs, tmpIfName, slaveIfName)
	if err != nil {
		return 0, fmt.Errorf("unable to setup ipvlan slave in remote netns: %s", err)
	}

	ep.DatapathMapID = int64(mapID)

	return mapFD, nil
}

// ConfigureNetNSForIPVLAN sets up IPVLAN in the specified network namespace.
// Returns the file descriptor for the tail call map / ID, and an error if
// any operation while configuring said namespace fails.
func ConfigureNetNSForIPVLAN(netNsPath string) (mapFD, mapID int, err error) {
	var ipvlanIface string
	// To access the netns, `/var/run/docker/netns` has to
	// be bind mounted into the cilium-agent container with
	// the `rshared` option to prevent from leaking netns
	netNs, err := ns.GetNS(netNsPath)
	if err != nil {
		return 0, 0, fmt.Errorf("Unable to open container netns %s: %s", netNsPath, err)
	}

	// Docker doesn't report about interfaces used to connect to
	// container network, so we need to scan all to find the ipvlan slave
	err = netNs.Do(func(ns.NetNS) error {
		links, err := netlink.LinkList()
		if err != nil {
			return err
		}
		for _, link := range links {
			if link.Type() == "ipvlan" &&
				strings.HasPrefix(link.Attrs().Name,
					ContainerInterfacePrefix) {
				ipvlanIface = link.Attrs().Name
				break
			}
		}
		if ipvlanIface == "" {
			return fmt.Errorf("ipvlan slave link not found")
		}
		return nil
	})
	if err != nil {
		return 0, 0, fmt.Errorf("Unable to find ipvlan slave in container netns: %s", err)
	}

	mapFD, mapID, err = setupIpvlanInRemoteNs(netNs,
		ipvlanIface, ipvlanIface)
	if err != nil {
		return 0, 0, fmt.Errorf("Unable to setup ipvlan slave: %s", err)
	}

	return mapFD, mapID, nil
}
