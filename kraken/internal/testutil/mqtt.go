package testutil

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
)

// MQTTConfig configures the mock MQTT broker behavior.
type MQTTConfig struct {
	AllowAnonymous  bool
	ValidUsers      map[string]string // username -> password
	AllowAllTopics  bool
	AllowedTopics   []string
	RetainMessages  bool
	MaxConnections  int
}

// DefaultMQTTConfig returns a permissive configuration for testing.
func DefaultMQTTConfig() MQTTConfig {
	return MQTTConfig{
		AllowAnonymous: true,
		AllowAllTopics: true,
		RetainMessages: true,
		MaxConnections: 100,
	}
}

// MockMQTTBroker implements a minimal MQTT 5.0 broker for testing.
type MockMQTTBroker struct {
	config   MQTTConfig
	listener net.Listener
	conns    map[string]net.Conn
	retained map[string][]byte
	wg       sync.WaitGroup
	closed   bool
	mu       sync.Mutex

	// Metrics for assertions
	ConnectCount    int
	PublishCount    int
	SubscribeCount  int
	DisconnectCount int
}

// NewMockMQTTBroker creates a mock MQTT broker.
func NewMockMQTTBroker(config MQTTConfig) *MockMQTTBroker {
	return &MockMQTTBroker{
		config:   config,
		conns:    make(map[string]net.Conn),
		retained: make(map[string][]byte),
	}
}

// Start starts the broker on a random port.
func (b *MockMQTTBroker) Start() error {
	var err error
	b.listener, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	b.wg.Add(1)
	go b.acceptLoop()
	return nil
}

func (b *MockMQTTBroker) acceptLoop() {
	defer b.wg.Done()
	for {
		conn, err := b.listener.Accept()
		if err != nil {
			b.mu.Lock()
			closed := b.closed
			b.mu.Unlock()
			if closed {
				return
			}
			continue
		}

		b.wg.Add(1)
		go func() {
			defer b.wg.Done()
			b.handleConnection(conn)
		}()
	}
}

func (b *MockMQTTBroker) handleConnection(conn net.Conn) {
	defer conn.Close()

	for {
		// Read fixed header
		header := make([]byte, 2)
		if _, err := io.ReadFull(conn, header); err != nil {
			return
		}

		packetType := (header[0] >> 4) & 0x0F
		remainingLength := int(header[1])

		// Handle multi-byte remaining length
		if remainingLength > 127 {
			// Simplified: read actual remaining length bytes
			var multiplier int = 128
			for {
				b := make([]byte, 1)
				if _, err := io.ReadFull(conn, b); err != nil {
					return
				}
				remainingLength += int(b[0]&127) * multiplier
				multiplier *= 128
				if b[0]&128 == 0 {
					break
				}
			}
		}

		// Read payload
		payload := make([]byte, remainingLength)
		if remainingLength > 0 {
			if _, err := io.ReadFull(conn, payload); err != nil {
				return
			}
		}

		switch packetType {
		case 1: // CONNECT
			b.mu.Lock()
			b.ConnectCount++
			b.mu.Unlock()
			b.handleConnect(conn, payload)
		case 3: // PUBLISH
			b.mu.Lock()
			b.PublishCount++
			b.mu.Unlock()
			b.handlePublish(conn, header[0], payload)
		case 8: // SUBSCRIBE
			b.mu.Lock()
			b.SubscribeCount++
			b.mu.Unlock()
			b.handleSubscribe(conn, payload)
		case 10: // UNSUBSCRIBE
			b.handleUnsubscribe(conn, payload)
		case 12: // PINGREQ
			b.handlePing(conn)
		case 14: // DISCONNECT
			b.mu.Lock()
			b.DisconnectCount++
			b.mu.Unlock()
			return
		}
	}
}

func (b *MockMQTTBroker) handleConnect(conn net.Conn, payload []byte) {
	// Parse CONNECT packet (simplified)
	// Protocol name length (2) + "MQTT" (4) + version (1) + flags (1) + keepalive (2)
	if len(payload) < 10 {
		b.sendConnack(conn, 0x81) // Malformed packet
		return
	}

	// Skip protocol name and version
	idx := 6
	if payload[idx] != 5 { // MQTT 5.0
		// Also accept 4 (MQTT 3.1.1) for broader compatibility
		if payload[idx] != 4 {
			b.sendConnack(conn, 0x84) // Unsupported protocol version
			return
		}
	}
	idx++

	flags := payload[idx]
	idx++
	// keepAlive := binary.BigEndian.Uint16(payload[idx:])
	idx += 2

	// MQTT 5.0: Properties length
	if payload[6] == 5 && idx < len(payload) {
		propsLen := int(payload[idx])
		idx += 1 + propsLen
	}

	// Client ID
	if idx+2 > len(payload) {
		b.sendConnack(conn, 0x81)
		return
	}
	clientIDLen := int(binary.BigEndian.Uint16(payload[idx:]))
	idx += 2
	if idx+clientIDLen > len(payload) {
		b.sendConnack(conn, 0x81)
		return
	}
	clientID := string(payload[idx : idx+clientIDLen])
	idx += clientIDLen

	// Check authentication
	hasUsername := (flags & 0x80) != 0
	hasPassword := (flags & 0x40) != 0

	if !b.config.AllowAnonymous && !hasUsername {
		b.sendConnack(conn, 0x86) // Bad username or password
		return
	}

	if hasUsername && len(b.config.ValidUsers) > 0 {
		// Parse username
		if idx+2 > len(payload) {
			b.sendConnack(conn, 0x81)
			return
		}
		usernameLen := int(binary.BigEndian.Uint16(payload[idx:]))
		idx += 2
		if idx+usernameLen > len(payload) {
			b.sendConnack(conn, 0x81)
			return
		}
		username := string(payload[idx : idx+usernameLen])
		idx += usernameLen

		var password string
		if hasPassword {
			if idx+2 > len(payload) {
				b.sendConnack(conn, 0x81)
				return
			}
			passwordLen := int(binary.BigEndian.Uint16(payload[idx:]))
			idx += 2
			if idx+passwordLen > len(payload) {
				b.sendConnack(conn, 0x81)
				return
			}
			password = string(payload[idx : idx+passwordLen])
		}

		expectedPassword, ok := b.config.ValidUsers[username]
		if !ok || expectedPassword != password {
			b.sendConnack(conn, 0x86) // Bad username or password
			return
		}
	}

	// Store connection
	b.mu.Lock()
	b.conns[clientID] = conn
	b.mu.Unlock()

	b.sendConnack(conn, 0x00) // Success
}

func (b *MockMQTTBroker) sendConnack(conn net.Conn, reasonCode byte) {
	// CONNACK: type(1) + remaining(1) + flags(1) + reason(1) + props(1)
	connack := []byte{0x20, 0x03, 0x00, reasonCode, 0x00}
	conn.Write(connack)
}

func (b *MockMQTTBroker) handlePublish(conn net.Conn, flags byte, payload []byte) {
	qos := (flags >> 1) & 0x03
	retain := (flags & 0x01) != 0

	// Parse topic
	if len(payload) < 2 {
		return
	}
	topicLen := int(binary.BigEndian.Uint16(payload))
	if len(payload) < 2+topicLen {
		return
	}
	topic := string(payload[2 : 2+topicLen])
	idx := 2 + topicLen

	// Packet ID for QoS > 0
	var packetID uint16
	if qos > 0 {
		if len(payload) < idx+2 {
			return
		}
		packetID = binary.BigEndian.Uint16(payload[idx:])
		idx += 2
	}

	// MQTT 5.0 properties
	if idx < len(payload) {
		propsLen := int(payload[idx])
		idx += 1 + propsLen
	}

	// Message payload
	message := payload[idx:]

	// Store retained message
	if retain && b.config.RetainMessages {
		b.mu.Lock()
		if len(message) == 0 {
			delete(b.retained, topic)
		} else {
			b.retained[topic] = message
		}
		b.mu.Unlock()
	}

	// Send PUBACK for QoS 1
	if qos == 1 {
		puback := []byte{0x40, 0x02}
		puback = append(puback, byte(packetID>>8), byte(packetID))
		conn.Write(puback)
	}
}

func (b *MockMQTTBroker) handleSubscribe(conn net.Conn, payload []byte) {
	if len(payload) < 2 {
		return
	}

	packetID := binary.BigEndian.Uint16(payload)
	idx := 2

	// MQTT 5.0 properties
	if idx < len(payload) {
		propsLen := int(payload[idx])
		idx += 1 + propsLen
	}

	var reasonCodes []byte

	// Parse topic filters
	for idx < len(payload) {
		if idx+2 > len(payload) {
			break
		}
		topicLen := int(binary.BigEndian.Uint16(payload[idx:]))
		idx += 2
		if idx+topicLen > len(payload) {
			break
		}
		// topic := string(payload[idx : idx+topicLen])
		idx += topicLen

		// Subscription options
		if idx >= len(payload) {
			break
		}
		// options := payload[idx]
		idx++

		// Grant QoS 0 for all subscriptions
		reasonCodes = append(reasonCodes, 0x00)
	}

	// Send SUBACK
	suback := bytes.Buffer{}
	suback.WriteByte(0x90) // SUBACK

	// Remaining length: packet ID (2) + props (1) + reason codes
	remainingLen := 2 + 1 + len(reasonCodes)
	suback.WriteByte(byte(remainingLen))
	suback.WriteByte(byte(packetID >> 8))
	suback.WriteByte(byte(packetID))
	suback.WriteByte(0x00) // Properties length
	suback.Write(reasonCodes)

	conn.Write(suback.Bytes())
}

func (b *MockMQTTBroker) handleUnsubscribe(conn net.Conn, payload []byte) {
	if len(payload) < 2 {
		return
	}

	packetID := binary.BigEndian.Uint16(payload)

	// Send UNSUBACK
	unsuback := []byte{0xB0, 0x03, byte(packetID >> 8), byte(packetID), 0x00}
	conn.Write(unsuback)
}

func (b *MockMQTTBroker) handlePing(conn net.Conn) {
	// PINGRESP
	conn.Write([]byte{0xD0, 0x00})
}

// Stop stops the broker.
func (b *MockMQTTBroker) Stop() error {
	b.mu.Lock()
	b.closed = true
	for _, conn := range b.conns {
		conn.Close()
	}
	b.mu.Unlock()

	if b.listener != nil {
		b.listener.Close()
	}
	b.wg.Wait()
	return nil
}

// Addr returns the broker address.
func (b *MockMQTTBroker) Addr() string {
	return b.listener.Addr().String()
}

// Port returns the broker port.
func (b *MockMQTTBroker) Port() int {
	return b.listener.Addr().(*net.TCPAddr).Port
}

// GetRetained returns a retained message for a topic.
func (b *MockMQTTBroker) GetRetained(topic string) []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.retained[topic]
}

// Reset resets the broker metrics.
func (b *MockMQTTBroker) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ConnectCount = 0
	b.PublishCount = 0
	b.SubscribeCount = 0
	b.DisconnectCount = 0
}
