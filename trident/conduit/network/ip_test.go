package network_test

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"bytemomo/trident/conduit"
	net "bytemomo/trident/conduit/network"
	"bytemomo/trident/conduit/utils"
)

var (
	vethIPNameA string
	vethIPNameB string
)

func TestMain(m *testing.M) {
	if os.Geteuid() != 0 {
		fmt.Println("Skipping network tests: must be run as root")
		os.Exit(0)
	}

	// Pick unique interface names to avoid collisions across runs.
	suffix := strconv.Itoa(os.Getpid() % 10000)
	vethIPNameA = "veth" + suffix
	vethIPNameB = "vetb" + suffix

	cleanup := func() {
		_ = exec.Command("ip", "link", "del", vethIPNameA).Run()
		_ = exec.Command("ip", "link", "del", vethIPNameB).Run()
	}
	exit := func(code int) {
		cleanup()
		os.Exit(code)
	}

	// Best-effort cleanup of stale interfaces.
	cleanup()

	// Create veth pair
	cmd := exec.Command("ip", "link", "add", vethIPNameA, "type", "veth", "peer", "name", vethIPNameB)
	if err := cmd.Run(); err != nil {
		fmt.Println("Skipping network tests: failed to create veth pair:", err)
		exit(0)
	}

	// Bring up veth interfaces
	cmd = exec.Command("ip", "link", "set", vethIPNameA, "up")
	if err := cmd.Run(); err != nil {
		fmt.Println("Skipping network tests: failed to bring up", vethIPNameA, ":", err)
		exit(0)
	}
	cmd = exec.Command("ip", "link", "set", vethIPNameB, "up")
	if err := cmd.Run(); err != nil {
		fmt.Println("Skipping network tests: failed to bring up", vethIPNameB, ":", err)
		exit(0)
	}

	// Assign IP addresses
	cmd = exec.Command("ip", "addr", "add", "192.168.1.1/24", "dev", vethIPNameA)
	if err := cmd.Run(); err != nil {
		fmt.Println("Skipping network tests: failed to assign IP to", vethIPNameA, ":", err)
		exit(0)
	}
	cmd = exec.Command("ip", "addr", "add", "192.168.1.2/24", "dev", vethIPNameB)
	if err := cmd.Run(); err != nil {
		fmt.Println("Skipping network tests: failed to assign IP to", vethIPNameB, ":", err)
		exit(0)
	}

	code := m.Run()
	exit(code)
}

func TestIpConduit_SendRecv(t *testing.T) {
	// Create conduits
	raddr, _ := netip.ParseAddr("192.168.1.2")
	conduit0 := net.IPRaw(253, raddr)
	conduit1 := net.IPRaw(253, netip.Addr{})

	// Dial conduits
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := conduit0.Dial(ctx); err != nil {
		t.Skipf("Skipping IP conduit test: raw socket not available (%v)", err)
	}
	defer conduit0.Close()
	if err := conduit1.Dial(ctx); err != nil {
		t.Skipf("Skipping IP conduit test: raw socket not available (%v)", err)
	}
	defer conduit1.Close()

	// Send a packet
	payload := []byte("hello world")
	buf := utils.GetBuf(len(payload))
	copy(buf.Bytes(), payload)
	pkt := &conduit.IPPacket{
		Data: buf,
		Dst:  raddr,
	}
	go func() {
		_, _, err := conduit0.Underlying().Send(ctx, pkt, nil)
		if err != nil {
			t.Error(err)
		}
	}()

	// Receive the packet
	recvPkt, err := conduit1.Underlying().Recv(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Check the payload
	if string(recvPkt.Data.Bytes()) != string(payload) {
		t.Errorf("unexpected payload: got %q, want %q", string(recvPkt.Data.Bytes()), string(payload))
	}
}
