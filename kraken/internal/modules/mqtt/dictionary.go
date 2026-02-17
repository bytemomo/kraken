package mqtt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/modules/dictionary"
	"bytemomo/kraken/internal/native"
	cnd "bytemomo/trident/conduit"

	"github.com/sirupsen/logrus"
)

var defaultMQTTCredentials = []dictionary.Credential{
	dictionary.NewCredential("admin", "admin", true),
	dictionary.NewCredential("admin", "1234", true),
	dictionary.NewCredential("admin", "12345", true),
	dictionary.NewCredential("admin", "", true),
	dictionary.NewCredential("root", "root", true),
	dictionary.NewCredential("root", "pass", true),
	dictionary.NewCredential("user", "user", true),
	dictionary.NewCredential("guest", "guest", true),
}

func registerDictionaryAttack() {
	native.Register("mqtt-dict-attack", native.Descriptor{
		Run:  runMQTTDictionaryAttack,
		Kind: cnd.KindStream,
		Stack: []domain.LayerHint{
			{Name: "tcp"},
		},
		Description: `Attempts MQTT CONNECT handshakes with a credential dictionary.
Reports valid username/password combinations and highlights default credentials when discovered.`,
	})
}

func runMQTTDictionaryAttack(ctx context.Context, mod *domain.Module, target domain.Target, res native.Resources, params map[string]any, timeout time.Duration) (domain.RunResult, error) {
	result := domain.RunResult{Target: target}
	if res.StreamFactory == nil {
		return result, errors.New("mqtt-dict-attack requires a stream conduit")
	}

	opts, err := parseMQTTDictOptions(params)
	if err != nil {
		return result, err
	}

	log := logrus.WithFields(logrus.Fields{
		"module": mod.ModuleID,
		"target": target.String(),
	})

	var lastErr error
	for idx, cred := range opts.Credentials {
		runCtx := ctx
		var cancel context.CancelFunc
		if timeout > 0 {
			runCtx, cancel = context.WithTimeout(ctx, timeout)
		}

		handle, cleanup, err := res.StreamFactory(runCtx)
		if err != nil {
			if cancel != nil {
				cancel()
			}
			return result, fmt.Errorf("dial conduit for credential %s/%s: %w", cred.Username, cred.Password, err)
		}

		stream, ok := handle.(cnd.Stream)
		if !ok {
			cleanup()
			if cancel != nil {
				cancel()
			}
			return result, fmt.Errorf("unexpected conduit type %T", handle)
		}

		clientID := fmt.Sprintf("%s-%03d", opts.ClientIDPrefix, idx+1)
		client := newMQTTClient(runCtx, stream)

		connectPkt := buildConnectPacket(connectPacketOptions{
			ClientID:          clientID,
			Username:          cred.Username,
			Password:          cred.Password,
			KeepAlive:         opts.KeepAlive,
			CleanStart:        opts.CleanStart,
			SendEmptyPassword: opts.AllowEmptyPassword,
			IncludeUsername:   cred.Username != "",
			IncludePassword:   cred.Password != "" || opts.AllowEmptyPassword,
		})

		err = client.sendPacket(connectPkt)
		if err != nil {
			cleanup()
			if cancel != nil {
				cancel()
			}
			lastErr = err
			log.WithError(err).Warnf("credential %s/%s send failed", cred.Username, cred.Password)
			result.Logs = append(result.Logs, fmt.Sprintf("[MQTT-DICT] %s/%s -> send error: %v", cred.Username, cred.Password, err))
			continue
		}

		resp, recvErr := client.recv(defaultTimeout)
		cleanup()
		if cancel != nil {
			cancel()
		}
		if recvErr != nil {
			lastErr = recvErr
			log.WithError(recvErr).Warnf("credential %s/%s recv failed", cred.Username, cred.Password)
			result.Logs = append(result.Logs, fmt.Sprintf("[MQTT-DICT] %s/%s -> recv error: %v", cred.Username, cred.Password, recvErr))
			continue
		}

		if len(resp) < 4 || resp[0] != 0x20 {
			lastErr = fmt.Errorf("unexpected response %x", resp)
			result.Logs = append(result.Logs, fmt.Sprintf("[MQTT-DICT] %s/%s -> unexpected response %x", cred.Username, cred.Password, resp))
			continue
		}

		reason := resp[3]
		result.Logs = append(result.Logs, fmt.Sprintf("[MQTT-DICT] %s/%s -> reason 0x%02x", cred.Username, cred.Password, reason))

		if reason == 0x00 {
			ev := map[string]any{
				"username":    cred.Username,
				"password":    cred.Password,
				"client_id":   clientID,
				"keep_alive":  opts.KeepAlive,
				"reason_code": reason,
			}

			result.Findings = append(result.Findings, domain.Finding{
				ID:          "MQTT-VALID-CREDS",
				ModuleID:    mod.ModuleID,
				Success:     true,
				Title:       "MQTT dictionary attack succeeded",
				Severity:    "high",
				Description: fmt.Sprintf("Broker accepted CONNECT with %s/%s.", cred.Username, cred.Password),
				Evidence:    ev,
				Tags:        []domain.Tag{"protocol:mqtt"},
				Timestamp:   time.Now().UTC(),
				Target:      target,
			})

			if cred.IsDefault {
				result.Findings = append(result.Findings, domain.Finding{
					ID:          "DEFAULT-CREDENTIALS",
					ModuleID:    mod.ModuleID,
					Success:     true,
					Title:       "Default MQTT credential discovered",
					Severity:    "high",
					Description: fmt.Sprintf("Broker accepted default credential %s/%s.", cred.Username, cred.Password),
					Evidence:    ev,
					Tags:        []domain.Tag{"protocol:mqtt"},
					Timestamp:   time.Now().UTC(),
					Target:      target,
				})
			}

			log.WithField("username", cred.Username).Info("dictionary attack succeeded")
			return result, nil
		}
	}

	if len(result.Findings) == 0 {
		result.Findings = append(result.Findings, domain.Finding{
			ID:          "MQTT-VALID-CREDS",
			ModuleID:    mod.ModuleID,
			Success:     false,
			Title:       "MQTT dictionary attack",
			Severity:    "info",
			Description: fmt.Sprintf("No credential matched after %d attempts.", len(opts.Credentials)),
			Tags:        []domain.Tag{"protocol:mqtt"},
			Timestamp:   time.Now().UTC(),
			Target:      target,
		})
	}

	return result, lastErr
}

type mqttDictOptions struct {
	ClientIDPrefix     string
	KeepAlive          uint16
	CleanStart         bool
	AllowEmptyPassword bool
	Credentials        []dictionary.Credential
}

func parseMQTTDictOptions(params map[string]any) (mqttDictOptions, error) {
	opts := mqttDictOptions{
		ClientIDPrefix:     "kraken-dict",
		KeepAlive:          30,
		CleanStart:         true,
		AllowEmptyPassword: true,
	}

	if params != nil {
		if cid, ok := params["client_id"].(string); ok && cid != "" {
			opts.ClientIDPrefix = cid
		}
		if ka, ok := params["keep_alive"].(int); ok && ka > 0 && ka <= 65535 {
			opts.KeepAlive = uint16(ka)
		} else if kaf, ok := params["keep_alive"].(float64); ok && kaf > 0 && kaf <= 65535 {
			opts.KeepAlive = uint16(kaf)
		}
		if cs, ok := params["clean_start"].(bool); ok {
			opts.CleanStart = cs
		}
		if allowEmpty, ok := params["allow_empty_password"].(bool); ok {
			opts.AllowEmptyPassword = allowEmpty
		}
	}

	creds, err := dictionary.LoadCredentials(params, defaultMQTTCredentials)
	if err != nil {
		return opts, err
	}
	opts.Credentials = creds
	return opts, nil
}

type connectPacketOptions struct {
	ClientID          string
	Username          string
	Password          string
	KeepAlive         uint16
	CleanStart        bool
	SendEmptyPassword bool
	IncludeUsername   bool
	IncludePassword   bool
}

func buildConnectPacket(opts connectPacketOptions) []byte {
	var vh bytes.Buffer
	writeString(&vh, "MQTT")
	vh.WriteByte(0x05) // protocol level

	flags := byte(0)
	if opts.CleanStart {
		flags |= 0x02
	}
	if opts.IncludeUsername {
		flags |= 0x80
	}
	if opts.IncludePassword {
		flags |= 0x40
	}
	vh.WriteByte(flags)
	vh.WriteByte(byte(opts.KeepAlive >> 8))
	vh.WriteByte(byte(opts.KeepAlive & 0xff))
	vh.WriteByte(0x00) // properties length

	var payload bytes.Buffer
	writeString(&payload, opts.ClientID)
	if opts.IncludeUsername {
		writeString(&payload, opts.Username)
	}
	if opts.IncludePassword {
		if opts.Password != "" || opts.SendEmptyPassword {
			writeString(&payload, opts.Password)
		}
	}

	remainingLength := vh.Len() + payload.Len()
	var packet bytes.Buffer
	packet.WriteByte(0x10) // CONNECT
	encodeVarInt(&packet, remainingLength)
	packet.Write(vh.Bytes())
	packet.Write(payload.Bytes())
	return packet.Bytes()
}

func writeString(buf *bytes.Buffer, s string) {
	if buf == nil {
		return
	}
	b := []byte(s)
	length := len(b)
	buf.WriteByte(byte(length >> 8))
	buf.WriteByte(byte(length & 0xff))
	buf.Write(b)
}

func encodeVarInt(buf *bytes.Buffer, value int) {
	if buf == nil {
		return
	}
	for {
		encoded := byte(value % 128)
		value /= 128
		if value > 0 {
			encoded |= 128
		}
		buf.WriteByte(encoded)
		if value == 0 {
			break
		}
	}
}
