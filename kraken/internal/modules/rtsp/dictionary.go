package rtsp

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/modules/dictionary"
	"bytemomo/kraken/internal/native"
	cnd "bytemomo/trident/conduit"

	"github.com/sirupsen/logrus"
)

var defaultCredentialPairs = []dictionary.Credential{
	dictionary.NewCredential("admin", "admin", true),
	dictionary.NewCredential("admin", "12345", true),
	dictionary.NewCredential("admin", "1234", true),
	dictionary.NewCredential("admin", "", true),
	dictionary.NewCredential("root", "root", true),
	dictionary.NewCredential("root", "pass", true),
	dictionary.NewCredential("root", "", true),
	dictionary.NewCredential("user", "user", true),
	dictionary.NewCredential("operator", "operator", true),
	dictionary.NewCredential("guest", "guest", true),
}

func registerDictionaryAttack() {
	native.Register("rtsp-dict-attack", native.Descriptor{
		Run:  runDictionaryAttack,
		Kind: cnd.KindStream,
		Stack: []domain.LayerHint{
			{Name: "tcp"},
		},
		Description: `Performs a Basic Authentication dictionary attack against an RTSP endpoint.
Attempts a configurable list of username/password pairs via DESCRIBE requests and reports any successful combination.`,
	})
}

func runDictionaryAttack(ctx context.Context, mod *domain.Module, target domain.Target, res native.Resources, params map[string]any, timeout time.Duration) (domain.RunResult, error) {
	result := domain.RunResult{Target: target}
	hp, ok := target.(domain.HostPort)
	if !ok {
		return result, fmt.Errorf("rtsp-dict-attack requires network target, got %T", target)
	}
	if res.StreamFactory == nil {
		return result, errors.New("rtsp-dict-attack requires a stream conduit")
	}

	opts, err := parseDictionaryOptions(params)
	if err != nil {
		return result, err
	}

	log := logrus.WithFields(logrus.Fields{
		"module": mod.ModuleID,
		"target": target.String(),
	})

	// Try anonymous access first. If the server accepts a DESCRIBE with no
	// Authorization header, there is no auth — skip the credential loop.
	if anonResult, done := tryAnonymousProbe(ctx, mod, target, hp, res, opts, timeout, log); done {
		return anonResult, nil
	}

	var lastErr error

	for _, cred := range opts.Credentials {
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
			return result, fmt.Errorf("dial conduit for credentials %s/%s: %w", cred.Username, cred.Password, err)
		}

		stream, ok := handle.(cnd.Stream)
		if !ok {
			cleanup()
			if cancel != nil {
				cancel()
			}
			return result, fmt.Errorf("unexpected conduit type %T", handle)
		}

		client := newRTSPClient(runCtx, stream, hp, opts.UserAgent)
		success, resp, attemptErr := tryCredential(client, opts.Path, cred)
		cleanup()
		if cancel != nil {
			cancel()
		}

		if attemptErr != nil {
			lastErr = attemptErr
			log.WithError(attemptErr).Warnf("credential %s/%s failed due to error", cred.Username, cred.Password)
			result.Logs = append(result.Logs, fmt.Sprintf("[RTSP-DICT] %s/%s -> error: %v", cred.Username, cred.Password, attemptErr))
			continue
		}

		result.Logs = append(result.Logs, fmt.Sprintf("[RTSP-DICT] %s/%s -> status %d", cred.Username, cred.Password, resp.StatusCode))

		if success {
			evidence := map[string]any{
				"username":    cred.Username,
				"password":    cred.Password,
				"path":        opts.Path,
				"status_code": resp.StatusCode,
			}
			if server := resp.Header("server"); server != "" {
				evidence["server"] = server
			}

			f := domain.Finding{
				ID:          "RTSP-WEAK-AUTH",
				ModuleID:    mod.ModuleID,
				Success:     true,
				Title:       "RTSP dictionary attack succeeded",
				Severity:    "high",
				Description: fmt.Sprintf("RTSP DESCRIBE succeeded on %s using %s/%s.", opts.Path, cred.Username, cred.Password),
				Evidence:    evidence,
				Tags:        []domain.Tag{"protocol:rtsp"},
				Timestamp:   time.Now().UTC(),
				Target:      target,
			}
			result.Findings = append(result.Findings, f)

			if cred.IsDefault {
				result.Findings = append(result.Findings, domain.Finding{
					ID:          "DEFAULT-CREDENTIALS",
					ModuleID:    mod.ModuleID,
					Success:     true,
					Title:       "Default RTSP credential discovered",
					Severity:    "high",
					Description: fmt.Sprintf("RTSP service accepted default credential %s/%s on %s.", cred.Username, cred.Password, opts.Path),
					Evidence:    evidence,
					Tags:        []domain.Tag{"protocol:rtsp"},
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
			ID:          "RTSP-WEAK-AUTH",
			ModuleID:    mod.ModuleID,
			Success:     false,
			Title:       "RTSP dictionary attack",
			Severity:    "info",
			Description: fmt.Sprintf("No credential matched after %d attempts.", len(opts.Credentials)),
			Tags:        []domain.Tag{"protocol:rtsp"},
			Timestamp:   time.Now().UTC(),
			Target:      target,
		})
	}

	return result, lastErr
}

func tryAnonymousProbe(ctx context.Context, mod *domain.Module, target domain.Target, hp domain.HostPort, res native.Resources, opts dictionaryOptions, timeout time.Duration, log *logrus.Entry) (domain.RunResult, bool) {
	result := domain.RunResult{Target: target}

	runCtx := ctx
	var cancel context.CancelFunc
	if timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	handle, cleanup, err := res.StreamFactory(runCtx)
	if err != nil {
		return result, false
	}

	stream, ok := handle.(cnd.Stream)
	if !ok {
		cleanup()
		return result, false
	}

	client := newRTSPClient(runCtx, stream, hp, opts.UserAgent)
	success, resp, anonErr := tryAnonymousDescribe(client, opts.Path)
	cleanup()

	if anonErr != nil {
		log.WithError(anonErr).Debug("anonymous DESCRIBE failed, proceeding with credentials")
		return result, false
	}
	if !success {
		return result, false
	}

	evidence := map[string]any{
		"path":        opts.Path,
		"status_code": resp.StatusCode,
	}
	if server := resp.Header("server"); server != "" {
		evidence["server"] = server
	}
	result.Findings = append(result.Findings, domain.Finding{
		ID:          "RTSP-NO-AUTH",
		ModuleID:    mod.ModuleID,
		Success:     true,
		Title:       "RTSP endpoint requires no authentication",
		Severity:    "high",
		Description: fmt.Sprintf("RTSP DESCRIBE succeeded on %s without any credentials — dictionary attack skipped.", opts.Path),
		Evidence:    evidence,
		Tags:        []domain.Tag{"protocol:rtsp"},
		Timestamp:   time.Now().UTC(),
		Target:      target,
	})
	result.Logs = append(result.Logs, fmt.Sprintf("[RTSP-DICT] anonymous -> status %d, skipping credential list", resp.StatusCode))
	log.Info("anonymous access accepted, skipping dictionary attack")
	return result, true
}

func tryAnonymousDescribe(client *rtspClient, path string) (bool, *rtspResponse, error) {
	headers := map[string]string{
		"Accept": "application/sdp",
	}
	uri := client.urlForPath(path)
	if err := client.sendRequest("DESCRIBE", uri, headers, ""); err != nil {
		return false, nil, err
	}
	resp, err := client.recvResponse(defaultTimeout)
	if err != nil {
		return false, nil, err
	}

	switch resp.StatusCode {
	case 200, 206:
		return true, resp, nil
	default:
		return false, resp, nil
	}
}

func tryCredential(client *rtspClient, path string, cred dictionary.Credential) (bool, *rtspResponse, error) {
	headers := map[string]string{
		"Accept":        "application/sdp",
		"Authorization": "Basic " + encodeBasicAuth(cred.Username, cred.Password),
	}
	uri := client.urlForPath(path)
	if err := client.sendRequest("DESCRIBE", uri, headers, ""); err != nil {
		return false, nil, err
	}
	resp, err := client.recvResponse(defaultTimeout)
	if err != nil {
		return false, nil, err
	}

	switch resp.StatusCode {
	case 200, 206:
		return true, resp, nil
	case 401, 403:
		return false, resp, nil
	default:
		return false, resp, nil
	}
}

type dictionaryOptions struct {
	Path        string
	UserAgent   string
	Credentials []dictionary.Credential
}

func parseDictionaryOptions(params map[string]any) (dictionaryOptions, error) {
	opts := dictionaryOptions{
		Path:      "/",
		UserAgent: defaultUserAgent,
	}

	if params != nil {
		if path, ok := params["path"].(string); ok && strings.TrimSpace(path) != "" {
			opts.Path = normalizeRTSPPath(path)
		}
		if path, ok := params["probe_path"].(string); ok && strings.TrimSpace(path) != "" {
			opts.Path = normalizeRTSPPath(path)
		}
		if ua, ok := params["user_agent"].(string); ok && strings.TrimSpace(ua) != "" {
			opts.UserAgent = ua
		}
	}

	creds, err := dictionary.LoadCredentials(params, defaultCredentialPairs)
	if err != nil {
		return opts, err
	}
	opts.Credentials = creds

	return opts, nil
}

func encodeBasicAuth(user, pass string) string {
	token := fmt.Sprintf("%s:%s", user, pass)
	return base64.StdEncoding.EncodeToString([]byte(token))
}
