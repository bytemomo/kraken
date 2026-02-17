package domain

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
)

// TargetKind identifies the type of target.
type TargetKind string

const (
	TargetKindNetwork   TargetKind = "network"
	TargetKindEtherCAT  TargetKind = "ethercat"
	TargetKindContainer TargetKind = "container"
)

// Target is the unified interface for scan targets.
type Target interface {
	Kind() TargetKind
	String() string
	Key() string
}

// HostPort represents a host and port combination.
type HostPort struct {
	Host string `json:"host"`
	Port uint16 `json:"port"`
}

func (h HostPort) Kind() TargetKind { return TargetKindNetwork }

func (h HostPort) String() string {
	return net.JoinHostPort(h.Host, strconv.Itoa(int(h.Port)))
}

func (h HostPort) Key() string { return h.String() }

// ContainerTarget represents a container target for fuzz campaigns.
type ContainerTarget struct {
	Image string
}

func (c ContainerTarget) Kind() TargetKind { return TargetKindContainer }

func (c ContainerTarget) String() string { return c.Image }

func (c ContainerTarget) Key() string { return "container:" + c.Image }

func (c ContainerTarget) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Image string `json:"image"`
	}{Image: c.Image})
}

// EtherCATMaster represents a discovered EtherCAT master on the network.
type EtherCATMaster struct {
	Interface  string           // Network interface where master was observed
	MACAddress net.HardwareAddr // Master's MAC address
	SlaveCount int              // Number of slaves observed
	Slaves     []uint16         // Station addresses of slaves seen
}

func (e EtherCATMaster) Kind() TargetKind { return TargetKindEtherCAT }

func (e EtherCATMaster) String() string {
	return fmt.Sprintf("ethercat://%s/master/%s", e.Interface, e.MACAddress)
}

func (e EtherCATMaster) Key() string {
	return fmt.Sprintf("ecat-master:%s:%s", e.Interface, e.MACAddress)
}

// MarshalJSON formats EtherCATMaster with MAC address as a readable string.
func (e EtherCATMaster) MarshalJSON() ([]byte, error) {
	type Alias struct {
		Interface  string   `json:"interface"`
		MACAddress string   `json:"mac_address"`
		SlaveCount int      `json:"slave_count"`
		Slaves     []uint16 `json:"slaves,omitempty"`
	}
	return json.Marshal(Alias{
		Interface:  e.Interface,
		MACAddress: e.MACAddress.String(),
		SlaveCount: e.SlaveCount,
		Slaves:     e.Slaves,
	})
}
