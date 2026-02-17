package datalink_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"bytemomo/trident/conduit"
	dl "bytemomo/trident/conduit/datalink"
	"bytemomo/trident/conduit/utils"
)

var (
	vethNameA string
	vethNameB string
)

func TestMain(m *testing.M) {
	if os.Geteuid() != 0 {
		fmt.Println("Skipping datalink tests: must be run as root")
		os.Exit(0)
	}

	// Pick unique interface names to avoid collisions across runs.
	suffix := strconv.Itoa(os.Getpid() % 10000)
	vethNameA = "veth" + suffix
	vethNameB = "veta" + suffix

	cleanup := func() {
		_ = exec.Command("ip", "link", "del", vethNameA).Run()
		_ = exec.Command("ip", "link", "del", vethNameB).Run()
	}
	exit := func(code int) {
		cleanup()
		os.Exit(code)
	}

	// Best-effort cleanup of stale interfaces from previous runs.
	cleanup()

	// Create veth pair
	cmd := exec.Command("ip", "link", "add", vethNameA, "type", "veth", "peer", "name", vethNameB)
	if err := cmd.Run(); err != nil {
		fmt.Println("Skipping datalink tests: failed to create veth pair:", err)
		exit(0)
	}

	// Bring up veth interfaces
	cmd = exec.Command("ip", "link", "set", vethNameA, "up")
	if err := cmd.Run(); err != nil {
		fmt.Println("Skipping datalink tests: failed to bring up", vethNameA, ":", err)
		exit(0)
	}
	cmd = exec.Command("ip", "link", "set", vethNameB, "up")
	if err := cmd.Run(); err != nil {
		fmt.Println("Skipping datalink tests: failed to bring up", vethNameB, ":", err)
		exit(0)
	}

	// Promisc helps when capturing non-IP EtherType frames.
	_ = exec.Command("ip", "link", "set", vethNameA, "promisc", "on").Run()
	_ = exec.Command("ip", "link", "set", vethNameB, "promisc", "on").Run()

	code := m.Run()
	exit(code)
}

func TestEthernetConduit_SendRecv(t *testing.T) {
	// Get interfaces
	veth0, err := net.InterfaceByName(vethNameA)
	if err != nil {
		t.Fatal(err)
	}
	veth1, err := net.InterfaceByName(vethNameB)
	if err != nil {
		t.Fatal(err)
	}

	// Create conduits
	// Use ETH_P_ALL (0) to avoid kernel filters dropping non-IP EtherType during capture.
	conduit0 := dl.Ethernet(vethNameA, veth1.HardwareAddr, 0)
	conduit1 := dl.Ethernet(vethNameB, veth0.HardwareAddr, 0)

	// Dial conduits
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := conduit0.Dial(ctx); err != nil {
		t.Fatal(err)
	}
	defer conduit0.Close()
	if err := conduit1.Dial(ctx); err != nil {
		t.Fatal(err)
	}
	defer conduit1.Close()

	// allow link state to settle
	time.Sleep(100 * time.Millisecond)

	if conduit0.Kind() != conduit.KindFrame {
		t.Fatalf("kind=%v want frame", conduit0.Kind())
	}
	if stack := conduit0.Stack(); len(stack) != 1 || stack[0] != "eth" {
		t.Fatalf("unexpected stack: %v", stack)
	}

	// Send a frame
	payload := []byte("hello world")
	buf := utils.GetBuf(len(payload))
	copy(buf.Bytes(), payload)
	pkt := &conduit.FramePkt{
		Data:      buf,
		Dst:       veth1.HardwareAddr,
		EtherType: dl.EtherTypeEtherCAT,
	}
	if _, _, err := conduit0.Underlying().Send(ctx, pkt, nil); err != nil {
		t.Fatalf("send: %v", err)
	}

	// Receive the frame
	recvCtx, recvCancel := context.WithTimeout(ctx, 5*time.Second)
	defer recvCancel()
	recvPkt, err := conduit1.Underlying().Recv(recvCtx, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Check the payload
	if string(recvPkt.Data.Bytes()) != string(payload) {
		t.Errorf("unexpected payload: got %q, want %q", string(recvPkt.Data.Bytes()), string(payload))
	}
	if recvPkt.EtherType != dl.EtherTypeEtherCAT {
		t.Errorf("unexpected ether type: got 0x%x want 0x%x", recvPkt.EtherType, dl.EtherTypeEtherCAT)
	}
}
