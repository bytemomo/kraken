package ethercat

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"bytemomo/kraken/internal/domain"

	"github.com/Aruminium/goecat/pkg/ethercat/command"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
)

// Scanner passively sniffs EtherCAT traffic to discover masters.
type Scanner struct {
	Log    *logrus.Entry
	Config domain.EtherCATScannerConfig
}

func New(log *logrus.Entry, cfg domain.EtherCATScannerConfig) *Scanner {
	return &Scanner{Log: log, Config: cfg}
}

func (s *Scanner) Type() string { return "ethercat" }

func (s *Scanner) Execute(ctx context.Context) ([]domain.ClassifiedTarget, error) {
	if s.Config.Interface == "" {
		return nil, fmt.Errorf("ethercat: interface not specified")
	}

	log := s.Log.WithField("iface", s.Config.Interface)
	log.Info("Starting EtherCAT sniffer")

	timeout := s.Config.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	// Open pcap handle (promiscuous mode, 1600 byte snaplen)
	handle, err := pcap.OpenLive(s.Config.Interface, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("ethercat: pcap open failed: %w", err)
	}
	defer handle.Close()

	// Get local MAC to filter our own frames
	ifc, err := net.InterfaceByName(s.Config.Interface)
	var localMAC net.HardwareAddr
	if err == nil {
		localMAC = ifc.HardwareAddr
	}

	masters := make(map[string]*masterInfo)
	slaves := make(map[uint16]bool)

	log.WithField("timeout", timeout).Info("Sniffing for EtherCAT traffic")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.NoCopy = true

	frameCount := 0
	recvCount := 0
	skippedOwn := 0
	skippedType := 0

	deadline := time.After(timeout)
	for {
		select {
		case <-ctx.Done():
			goto done
		case <-deadline:
			goto done
		case packet := <-packetSource.Packets():
			if packet == nil {
				continue
			}
			recvCount++

			data := packet.Data()
			if len(data) < 14 {
				continue
			}

			// Parse ethernet header
			srcMAC := net.HardwareAddr(data[6:12])
			etherType := uint16(data[12])<<8 | uint16(data[13])

			// Skip our own frames
			if localMAC != nil && srcMAC.String() == localMAC.String() {
				skippedOwn++
				continue
			}

			// Skip broadcast source (not a real master)
			if srcMAC.String() == "ff:ff:ff:ff:ff:ff" {
				continue
			}

			// Only process EtherCAT frames
			if etherType != EtherTypeEtherCAT {
				skippedType++
				continue
			}

			frameCount++
			s.processFrame(data, srcMAC, masters, slaves)
		}
	}

done:
	log.WithFields(logrus.Fields{
		"frames":       frameCount,
		"masters":      len(masters),
		"slaves":       len(slaves),
		"recv_total":   recvCount,
		"skipped_own":  skippedOwn,
		"skipped_type": skippedType,
	}).Info("Sniffing complete")

	var targets []domain.ClassifiedTarget
	for _, m := range masters {
		master := domain.EtherCATMaster{
			Interface:  s.Config.Interface,
			MACAddress: m.mac,
			SlaveCount: len(m.slaves),
			Slaves:     m.slaves,
		}
		targets = append(targets, domain.ClassifiedTarget{
			Target: master,
			Tags:   []domain.Tag{"protocol:ethercat", "role:master"},
		})
	}

	return targets, nil
}

type masterInfo struct {
	mac      net.HardwareAddr
	slaves   []uint16
	lastSeen time.Time
}

func (s *Scanner) processFrame(data []byte, srcMAC net.HardwareAddr, masters map[string]*masterInfo, slaves map[uint16]bool) {
	if len(data) < 16 { // Eth header (14) + EtherCAT header (2) minimum
		return
	}

	ecatData := data[14:]
	header := binary.LittleEndian.Uint16(ecatData[0:2])
	length := header & 0x7FF
	ecatType := (header >> 12) & 0x0F

	if ecatType != 1 {
		return
	}

	macStr := srcMAC.String()
	master, exists := masters[macStr]
	if !exists {
		master = &masterInfo{mac: srcMAC}
		masters[macStr] = master
		s.Log.WithField("mac", macStr).Info("Discovered EtherCAT master")
	}
	master.lastSeen = time.Now()

	// Parse datagrams to find slave addresses
	offset := 2
	for offset < int(length)+2 {
		if offset+10 > len(ecatData) {
			break
		}

		cmd := command.Type(ecatData[offset])
		addr := binary.LittleEndian.Uint32(ecatData[offset+2 : offset+6])
		lenFlags := binary.LittleEndian.Uint16(ecatData[offset+6 : offset+8])
		dataLen := int(lenFlags & 0x7FF)
		more := (lenFlags & 0x8000) != 0

		// Extract slave station address from configured address commands
		if cmd == command.FPRD || cmd == command.FPWR || cmd == command.FPRW {
			stationAddr := uint16(addr & 0xFFFF)
			if stationAddr != 0 && stationAddr != 0xFFFF && !slaves[stationAddr] {
				slaves[stationAddr] = true
				s.Log.WithField("addr", fmt.Sprintf("0x%04X", stationAddr)).Debug("Found slave")

				found := false
				for _, a := range master.slaves {
					if a == stationAddr {
						found = true
						break
					}
				}
				if !found {
					master.slaves = append(master.slaves, stationAddr)
				}
			}
		}

		offset += 10 + dataLen + 2
		if !more {
			break
		}
	}
}
