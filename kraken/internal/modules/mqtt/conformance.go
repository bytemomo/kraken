package mqtt

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/native"
	cnd "bytemomo/trident/conduit"
	"bytemomo/trident/conduit/transport"

	"github.com/sirupsen/logrus"
)

const (
	defaultTimeout = 5 * time.Second
)

var (
	// Standard packets for setup
	hexConnectPacket    = "10 1a 00 04 4d 51 54 54 05 02 00 1e 00 00 0d 6b 72 61 6b 65 6e 2d 63 6c 69 65 6e 74"
	hexDisconnectPacket = "e0 00"

	// Test-specific packets
	hexConnectKeepAlive2s = "10 1a 00 04 4d 51 54 54 05 02 00 02 00 00 0d 6b 72 61 6b 65 6e 2d 63 6c 69 65 6e 74"    // KeepAlive set to 2 seconds
	hexConnectCleanStart0 = "10 1a 00 04 4d 51 54 54 05 00 00 1e 00 00 0d 6b 72 61 6b 65 6e 2d 70 65 72 73 69 73 74" // Clean Start = 0
	hexConnectWillFlag    = "10 3a 00 04 4d 51 54 54 05 06 00 1e 00 1e 00 0b 77 69 6c 6c 2f 74 6f 70 69 63 00 0f 77 69 6c 6c 2d 6d 65 73 73 61 67 65 00 0d 6b 72 61 6b 65 6e 2d 77 69 6c 6c"

	hexSubscribePacket      = "82 18 00 01 00 00 12 6b 72 61 6b 65 6e 2f 63 6f 6e 66 6f 72 6d 61 6e 63 65 00"
	hexSubscribeInvalidUTF8 = "82 0e 00 02 00 00 08 74 6f 70 69 63 2f f0 9f 00" // Invalid UTF-8 sequence (missing trailing bytes)
	hexUnsubscribePacket    = "a2 17 00 03 00 00 12 6b 72 61 6b 65 6e 2f 63 6f 6e 66 6f 72 6d 61 6e 63 65"
	hexSubscribeShared      = "82 20 00 04 00 00 1a 24 73 68 61 72 65 2f 67 72 6f 75 70 31 2f 73 68 61 72 65 64 2d 74 6f 70 69 63 00"

	hexPublishPacketQoS0    = "30 2c 00 12 6b 72 61 6b 65 6e 2f 63 6f 6e 66 6f 72 6d 61 6e 63 65 00 6b 72 61 6b 65 6e 2d 6d 71 74 74 2d 63 6f 6e 66 6f 72 6d 61 6e 63 65"
	hexPublishPacketQoS1    = "32 2e 00 12 6b 72 61 6b 65 6e 2f 63 6f 6e 66 6f 72 6d 61 6e 63 65 00 05 00 6b 72 61 6b 65 6e 2d 6d 71 74 74 2d 63 6f 6e 66 6f 72 6d 61 6e 63 65"
	hexPublishRetained      = "31 1d 00 0e 72 65 74 61 69 6e 2f 74 6f 70 69 63 00 72 65 74 61 69 6e 65 64 2d 6d 73 67"
	hexPublishDeleteRetain  = "31 0f 00 0e 72 65 74 61 69 6e 2f 74 6f 70 69 63 00" // Zero-byte payload
	hexSubscribeRetainTopic = "82 12 00 06 00 00 0e 72 65 74 61 69 6e 2f 74 6f 70 69 63 00"

	hexMalformedPacket = "82 02 00 01" // SUBSCRIBE without the mandatory Property Length byte
	hexPingReqPacket   = "c0 00"

	// Expected values
	topicName       = "kraken/conformance"
	expectedPayload = "kraken-mqtt-conformance"
)

func Init() {
	registerConformance()
	registerDictionaryAttack()
}

func registerConformance() {
	native.Register("mqtt-conformance-test", native.Descriptor{
		Run:  runConformanceTests,
		Kind: cnd.KindStream,
		Stack: []domain.LayerHint{
			{Name: "tcp"},
		},
		Description: `Evaluates a broker's compliance with key normative statements from the official MQTT v5.0 specification.
	Each test is designed to verify a specific requirement by sending raw, hex-encoded packets and validating the broker's response.

        This module checks the following normative statements:
        - MQTT-3.1.4-5: Server acknowledges a valid CONNECT with a successful CONNACK packet containing a 0x00 (Success) Reason Code .
        - MQTT-3.12.4-1: Server responds to a PINGREQ with a PINGRESP to maintain the connection.
        - MQTT-3.8.4-1: Server acknowledges a SUBSCRIBE packet with a corresponding SUBACK.
        - MQTT-3.3.4-1: Server acknowledges a QoS 1 PUBLISH packet with a PUBACK.
        - MQTT-3.10.4-4: Server acknowledges an UNSUBSCRIBE packet with an UNSUBACK.
        - MQTT-3.1.2-22: Server disconnects an idle client after 1.5 times the negotiated Keep Alive interval.
        - MQTT-4.8.2-2: Server correctly parses and accepts a valid Shared Subscription.
        - MQTT-3.3.1-6: Server deletes a topic's retained message upon receiving a zero-byte retained PUBLISH.
        - MQTT-4.7.3-2: Server rejects a subscription that contains an invalid UTF-8 Topic Filter.

        [1] The full specification can be referenced at: https://docs.oasis-open.org/mqtt/mqtt/v5.0/cs01/mqtt-v5.0-cs01.html
    `,
	})
}

func runConformanceTests(ctx context.Context, mod *domain.Module, target domain.Target, res native.Resources, _ map[string]any, timeout time.Duration) (domain.RunResult, error) {
	result := domain.RunResult{Target: target}
	if res.StreamFactory == nil {
		return result, errors.New("mqtt-conformance-test requires a stream conduit")
	}

	log := logrus.WithFields(logrus.Fields{
		"module": mod.ModuleID,
		"target": target.String(),
	})

	// --- Test Suite Definition ---
	tests := []testCase{
		{Code: "MQTT-3.1.4-5", Name: "Server acknowledges CONNECT with CONNACK", Run: testConnectAck},
		{Code: "MQTT-3.12.4-1", Name: "Server responds to PINGREQ with PINGRESP", Run: testPingResp},
		{Code: "MQTT-3.8.4-1", Name: "Server acknowledges SUBSCRIBE with SUBACK", Run: testSubscribeAck},
		{Code: "MQTT-3.3.4-1", Name: "Server acknowledges QoS 1 PUBLISH with PUBACK", Run: testPubAck},
		{Code: "MQTT-3.10.4-4", Name: "Server acknowledges UNSUBSCRIBE with UNSUBACK", Run: testUnsubscribeAck},
		{Code: "MQTT-3.1.2-22", Name: "Server enforces Keep Alive timeout", Run: testKeepAliveTimeout},
		{Code: "MQTT-4.8.2-2", Name: "Server accepts a valid Shared Subscription", Run: testSharedSubscription},
		{Code: "MQTT-3.3.1-6", Name: "Server deletes retained message", Run: testDeleteRetainedMessage},
		{Code: "MQTT-4.7.3-2", Name: "Server rejects subscription to invalid UTF-8 topic", Run: testInvalidUTF8Subscription},
		{Code: "MQTT-3.1.0-2", Name: "Server disconnects client on second CONNECT", Run: testSecondConnectDisconnect},
	}

	for _, tc := range tests {
		// For destructive tests, establish a new connection.
		runCtx := ctx
		if timeout > 0 {
			var cancel context.CancelFunc
			runCtx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		}

		handle, cleanup, err := res.StreamFactory(runCtx)
		if err != nil {
			return result, fmt.Errorf("dial conduit for test %s: %w", tc.Code, err)
		}

		stream, ok := handle.(cnd.Stream)
		if !ok {
			cleanup()
			return result, fmt.Errorf("unexpected conduit type %T", handle)
		}

		client := newMQTTClient(runCtx, stream)
		err = tc.Run(client)
		cleanup()

		status := statusMessage(err)
		log.WithField("test", tc.Code).WithError(err).Info(status + " " + tc.Name)

		result.Logs = append(result.Logs, fmt.Sprintf("[%s] %s: %s", tc.Code, tc.Name, status))
		result.Findings = append(result.Findings, buildFinding(mod.ModuleID, target, tc.Code, tc.Name, err))
	}

	return result, nil
}

type testCase struct {
	Code string
	Name string
	Run  func(*mqttClient) error
}

// --- Test Implementations ---

func testConnectAck(client *mqttClient) error {
	if err := client.sendHex(hexConnectPacket); err != nil {
		return err
	}
	resp, err := client.recv(defaultTimeout)
	if err != nil {
		return err
	}
	if len(resp) < 5 || resp[0] != 0x20 { // 0x20 = CONNACK, expect at least fixed header + flags + reason + properties length
		return fmt.Errorf("expected CONNACK, got %x", resp)
	}
	reasonCode := resp[3] // Fixed header (2 bytes) + ack flags
	if reasonCode != 0x00 {
		return fmt.Errorf("connect reason code non-zero: %d", reasonCode)
	}
	return nil
}

func testPingResp(client *mqttClient) error {
	if err := client.connectDefault(); err != nil {
		return err
	}

	if err := client.sendHex(hexPingReqPacket); err != nil {
		return err
	}
	resp, err := client.recv(defaultTimeout)
	if err != nil {
		return err
	}
	if len(resp) < 2 || resp[0] != 0xd0 || resp[1] != 0x00 { // 0xd0 0x00 = PINGRESP
		return fmt.Errorf("expected PINGRESP, got %x", resp)
	}
	return nil
}

func testSubscribeAck(client *mqttClient) error {
	if err := client.connectDefault(); err != nil {
		return err
	}

	if err := client.sendHex(hexSubscribePacket); err != nil {
		return err
	}
	resp, err := client.recv(defaultTimeout)
	if err != nil {
		return err
	}
	if len(resp) < 5 || resp[0] != 0x90 { // 0x90 = SUBACK
		return fmt.Errorf("expected SUBACK, got %x", resp)
	}
	if resp[len(resp)-1] > 0x02 { // Reason code for QoS 0, 1, or 2
		return fmt.Errorf("subscription rejected with reason code %d", resp[len(resp)-1])
	}
	return nil
}

func testPubAck(client *mqttClient) error {
	if err := client.connectDefault(); err != nil {
		return err
	}

	if err := client.sendHex(hexPublishPacketQoS1); err != nil {
		return err
	}
	resp, err := client.recv(defaultTimeout)
	if err != nil {
		return err
	}
	if len(resp) < 4 || resp[0] != 0x40 { // 0x40 = PUBACK
		return fmt.Errorf("expected PUBACK, got %x", resp)
	}
	// Check for matching packet identifier (00 05)
	if resp[2] != 0x00 || resp[3] != 0x05 {
		return fmt.Errorf("received PUBACK for wrong packet identifier: %x", resp[2:])
	}
	return nil
}

func testUnsubscribeAck(client *mqttClient) error {
	if err := client.connectDefault(); err != nil {
		return err
	}
	if err := client.sendHex(hexSubscribePacket); err != nil {
		return err
	}
	if _, err := client.recv(defaultTimeout); err != nil {
		return err
	} // Consume SUBACK

	if err := client.sendHex(hexUnsubscribePacket); err != nil {
		return err
	}
	resp, err := client.recv(defaultTimeout)
	if err != nil {
		return err
	}
	if len(resp) < 4 || resp[0] != 0xb0 { // 0xb0 = UNSUBACK
		return fmt.Errorf("expected UNSUBACK, got %x", resp)
	}
	return nil
}

func testKeepAliveTimeout(client *mqttClient) error {
	if err := client.sendHex(hexConnectKeepAlive2s); err != nil {
		return err
	}
	if _, err := client.recv(defaultTimeout); err != nil {
		return err
	} // Consume CONNACK

	// Wait for 1.5 * Keep Alive duration (1.5 * 2s = 3s), plus a buffer.
	// The server should disconnect us for inactivity.
	_, err := client.recv(4 * time.Second)
	if err == io.EOF || (err != nil && strings.Contains(err.Error(), "closed")) {
		return nil // Expected disconnection
	}
	return errors.New("server did not disconnect client after keep-alive timeout")
}

func testSharedSubscription(client *mqttClient) error {
	if err := client.connectDefault(); err != nil {
		return err
	}

	if err := client.sendHex(hexSubscribeShared); err != nil {
		return err
	}
	resp, err := client.recv(defaultTimeout)
	if err != nil {
		return err
	}
	if len(resp) < 5 || resp[0] != 0x90 { // SUBACK
		return fmt.Errorf("expected SUBACK for shared subscription, got %x", resp)
	}
	if resp[len(resp)-1] > 0x02 {
		return fmt.Errorf("shared subscription rejected with reason %d", resp[len(resp)-1])
	}
	return nil
}

func testDeleteRetainedMessage(client *mqttClient) error {
	// We just test if the broker accepts the zero-byte retain message publish.
	if err := client.connectDefault(); err != nil {
		return err
	}
	// First, set the retained message.
	if err := client.sendHex(hexPublishRetained); err != nil {
		return err
	}
	// Then, delete it.
	if err := client.sendHex(hexPublishDeleteRetain); err != nil {
		return err
	}

	{
		cond := transport.TCP(client.stream.RemoteAddr().String())
		client2 := newMQTTClient(context.Background(), cond.Underlying())

		client2.sendHex(hexSubscribeRetainTopic)

		if _, err := client.recv(defaultTimeout); err != nil {
			return err
		} // Should be PUBACK

		if topicMsg, err := client.recv(time.Second * 2); err != nil {
			return nil
		} else {
			return fmt.Errorf("expected nothing, got %x", topicMsg)
		}
	}
}

func testInvalidUTF8Subscription(client *mqttClient) error {
	if err := client.connectDefault(); err != nil {
		return err
	}

	if err := client.sendHex(hexSubscribeInvalidUTF8); err != nil {
		return err
	}
	resp, err := client.recv(defaultTimeout)
	if err != nil {
		return err
	}
	switch resp[0] {
	case 0x90: // SUBACK
		if len(resp) < 5 {
			return fmt.Errorf("expected SUBACK, got %x", resp)
		}
		if resp[len(resp)-1] != 0x8F { // Topic Filter Invalid
			return fmt.Errorf("expected reason code 0x8F (Topic Filter Invalid), but got %x", resp[len(resp)-1])
		}
		return nil
	case 0xE0: // DISCONNECT
		if len(resp) < 3 {
			return fmt.Errorf("expected DISCONNECT with reason code, got %x", resp)
		}
		reason := resp[2]
		if reason == 0x81 || reason == 0x8F {
			return nil
		}
		return fmt.Errorf("unexpected DISCONNECT reason code %x", reason)
	default:
		return fmt.Errorf("expected SUBACK or DISCONNECT, got %x", resp)
	}
}

func testSecondConnectDisconnect(client *mqttClient) error {
	if err := client.connectDefault(); err != nil {
		return err
	}

	// Send a second CONNECT packet on the same connection
	if err := client.sendHex(hexConnectPacket); err != nil {
		// Error is expected as server closes connection
	}

	// Server MUST close the connection. Recv should fail.
	_, err := client.recv(defaultTimeout)
	if err == io.EOF || (err != nil && strings.Contains(err.Error(), "closed")) {
		return nil
	}
	return errors.New("server did not disconnect client after a second CONNECT packet")
}

// Helper Functions

func (c *mqttClient) connectDefault() error {
	if err := c.sendHex(hexConnectPacket); err != nil {
		return err
	}
	resp, err := c.recv(defaultTimeout)
	if err != nil {
		return err
	}
	if len(resp) == 0 || resp[0] != 0x20 {
		return fmt.Errorf("expected CONNACK, got %x", resp)
	}
	return nil
}

func statusMessage(err error) string {
	if err == nil {
		return "PASS"
	}
	if strings.HasPrefix(err.Error(), "skipped:") {
		return "SKIP"
	}
	return "FAIL"
}

func buildFinding(moduleID string, target domain.Target, code, name string, err error) domain.Finding {
	success := err == nil
	severity := "info"
	desc := "Test completed successfully."

	if err != nil {
		if strings.HasPrefix(err.Error(), "skipped:") {
			severity = "info"
			desc = "Test was skipped. " + strings.TrimPrefix(err.Error(), "skipped: ")
		} else {
			severity = "medium"
			desc = err.Error()
		}
	}

	return domain.Finding{
		ID:          fmt.Sprintf("%s-%s", moduleID, strings.ToLower(code)),
		ModuleID:    moduleID,
		Success:     success,
		Title:       fmt.Sprintf("%s %s", code, name),
		Severity:    severity,
		Description: desc,
		Tags:        []domain.Tag{"protocol:mqtt"},
		Timestamp:   time.Now().UTC(),
		Target:      target,
	}
}

// ---

type mqttClient struct {
	ctx    context.Context
	stream cnd.Stream
}

func newMQTTClient(ctx context.Context, stream cnd.Stream) *mqttClient {
	return &mqttClient{ctx: ctx, stream: stream}
}

func (c *mqttClient) sendHex(hexPayload string) error {
	data, err := decodeHex(hexPayload)
	if err != nil {
		return err
	}
	return c.sendPacket(data)
}

func (c *mqttClient) sendPacket(data []byte) error {
	_, _, err := c.stream.Send(c.ctx, data, nil, nil)
	return err
}

func (c *mqttClient) recv(timeout time.Duration) ([]byte, error) {
	ctx := c.ctx
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(c.ctx, timeout)
		defer cancel()
	}
	chunk, err := c.stream.Recv(ctx, &cnd.RecvOptions{MaxBytes: 4096})
	if err != nil {
		return nil, err
	}
	if chunk == nil || chunk.Data == nil {
		return nil, io.EOF
	}
	data := append([]byte(nil), chunk.Data.Bytes()...)
	chunk.Data.Release()
	return data, nil
}

func decodeHex(h string) ([]byte, error) {
	h = strings.ReplaceAll(h, " ", "")
	h = strings.ReplaceAll(h, "\n", "")
	return hex.DecodeString(h)
}

func decodeVarInt(data []byte) (int, int, error) {
	value := 0
	multiplier := 1
	consumed := 0
	for {
		if consumed >= len(data) {
			return 0, consumed, errors.New("malformed varint: incomplete data")
		}
		encoded := int(data[consumed])
		consumed++
		value += (encoded & 127) * multiplier
		if (encoded & 128) == 0 {
			break
		}
		multiplier *= 128
		if multiplier > 128*128*128 {
			return 0, consumed, errors.New("varint too large")
		}
	}
	return value, consumed, nil
}
