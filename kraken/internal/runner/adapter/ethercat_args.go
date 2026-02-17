package adapter

import (
	"fmt"

	"bytemomo/kraken/internal/domain"
)

// buildEtherCATMasterArgs converts an EtherCATMaster to CLI arguments.
func buildEtherCATMasterArgs(master domain.EtherCATMaster) []string {
	args := []string{
		"--ecat-iface", master.Interface,
		"--ecat-master-mac", master.MACAddress.String(),
	}

	if master.SlaveCount > 0 {
		args = append(args, "--ecat-slave-count", fmt.Sprintf("%d", master.SlaveCount))
	}

	for _, addr := range master.Slaves {
		args = append(args, "--ecat-slave-addr", fmt.Sprintf("0x%04X", addr))
	}

	return args
}
