package rtsp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"bytemomo/kraken/internal/domain"
	"bytemomo/kraken/internal/native"
	cnd "bytemomo/trident/conduit"

	"github.com/sirupsen/logrus"
)

const (
	defaultTimeout   = 5 * time.Second
	defaultUserAgent = "Kraken-RTSP/1.0"
)

var defaultProbePaths = []string{
	"/",
	"/live.sdp",
	"/stream",
	"/stream1",
	"/video",
	"/h264",
	"/cam/realmonitor",
	"/axis-media/media.amp",
	"/ch1",
	"/ch0_0.h264",
}

func Init() {
	registerSurfaceScan()
	registerDictionaryAttack()
}

func registerSurfaceScan() {
	native.Register("rtsp-surface-scan", native.Descriptor{
		Run:  runSurfaceScan,
		Kind: cnd.KindStream,
		Stack: []domain.LayerHint{
			{Name: "tcp"},
		},
		Description: `Performs lightweight RTSP checks by issuing OPTIONS and DESCRIBE requests.
The module focuses on quickly identifying open playback paths or weak/basic authentication deployments.`,
	})
}

func runSurfaceScan(ctx context.Context, mod *domain.Module, target domain.Target, res native.Resources, params map[string]any, timeout time.Duration) (domain.RunResult, error) {
	result := domain.RunResult{Target: target}
	hp, ok := target.(domain.HostPort)
	if !ok {
		return result, fmt.Errorf("rtsp-surface-scan requires network target, got %T", target)
	}
	if res.StreamFactory == nil {
		return result, errors.New("rtsp-surface-scan requires a stream conduit")
	}

	opts := parseModuleOptions(params)

	log := logrus.WithFields(logrus.Fields{
		"module": mod.ModuleID,
		"target": target.String(),
	})

	tests := []testCase{
		{
			ID:              "RTSP-DISCOVERY",
			Name:            "RTSP Options Probe",
			SuccessSeverity: "info",
			FailureSeverity: "info",
			Tags:            []domain.Tag{"protocol:rtsp"},
			Run:             testOptionsDiscovery,
		},
		{
			ID:              "RTSP-OPEN-PLAYBACK",
			Name:            "Anonymous DESCRIBE (no auth)",
			SuccessSeverity: "high",
			FailureSeverity: "info",
			Tags:            []domain.Tag{"protocol:rtsp"},
			Run:             testAnonymousDescribe,
		},
		{
			ID:              "RTSP-BASIC-AUTH-USED",
			Name:            "Basic Authentication Challenge",
			SuccessSeverity: "medium",
			FailureSeverity: "info",
			Tags:            []domain.Tag{"protocol:rtsp"},
			Run:             testBasicChallenge,
		},
	}

	for _, tc := range tests {
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
			return result, fmt.Errorf("dial conduit for test %s: %w", tc.ID, err)
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
		outcome := tc.Run(client, opts)
		cleanup()
		if cancel != nil {
			cancel()
		}

		status := statusMessage(outcome.Err)
		log.WithField("test", tc.ID).WithError(outcome.Err).Info(status + " " + tc.Name)

		result.Logs = append(result.Logs, fmt.Sprintf("[%s] %s: %s", tc.ID, tc.Name, status))
		result.Findings = append(result.Findings, buildFinding(mod.ModuleID, target, tc, outcome))
	}

	return result, nil
}

type testCase struct {
	ID              string
	Name            string
	SuccessSeverity string
	FailureSeverity string
	Tags            []domain.Tag
	Run             func(*rtspClient, moduleOptions) testOutcome
}

type testOutcome struct {
	Err         error
	Description string
	Evidence    map[string]any
}

func testOptionsDiscovery(client *rtspClient, _ moduleOptions) testOutcome {
	if err := client.sendRequest("OPTIONS", "*", nil, ""); err != nil {
		return testOutcome{Err: err}
	}
	resp, err := client.recvResponse(defaultTimeout)
	if err != nil {
		return testOutcome{Err: err}
	}
	if resp.StatusCode != 200 && resp.StatusCode != 401 {
		return testOutcome{Err: fmt.Errorf("unexpected status %d from OPTIONS", resp.StatusCode)}
	}
	ev := map[string]any{
		"status_code": resp.StatusCode,
	}
	if server := resp.Header("server"); server != "" {
		ev["server"] = server
	}
	if public := resp.Header("public"); public != "" {
		ev["public_methods"] = parsePublicHeader(public)
	}
	desc := fmt.Sprintf("RTSP endpoint responded to OPTIONS with status %d.", resp.StatusCode)
	return testOutcome{Description: desc, Evidence: ev}
}

func testAnonymousDescribe(client *rtspClient, opts moduleOptions) testOutcome {
	var statuses []string
	for _, path := range opts.ProbePaths {
		uri := client.urlForPath(path)
		headers := map[string]string{"Accept": "application/sdp"}
		if err := client.sendRequest("DESCRIBE", uri, headers, ""); err != nil {
			return testOutcome{Err: err}
		}
		resp, err := client.recvResponse(defaultTimeout)
		if err != nil {
			return testOutcome{Err: err}
		}

		switch resp.StatusCode {
		case 200:
			ev := map[string]any{
				"path":         normalizeRTSPPath(path),
				"status_code":  resp.StatusCode,
				"content_type": resp.Header("content-type"),
			}
			if server := resp.Header("server"); server != "" {
				ev["server"] = server
			}
			if len(resp.Body) > 0 {
				ev["body_preview"] = snippet(string(resp.Body))
			}
			desc := fmt.Sprintf("DESCRIBE %s succeeded without authentication.", uri)
			return testOutcome{Description: desc, Evidence: ev}
		case 301, 302, 303, 307, 308:
			if loc := resp.Header("location"); loc != "" {
				return testOutcome{Err: fmt.Errorf("skipped: DESCRIBE redirected to %s", loc)}
			}
			return testOutcome{Err: fmt.Errorf("skipped: DESCRIBE redirected with status %d", resp.StatusCode)}
		default:
			statuses = append(statuses, fmt.Sprintf("%s=%d", normalizeRTSPPath(path), resp.StatusCode))
		}
	}
	if len(statuses) == 0 {
		return testOutcome{Err: errors.New("skipped: no DESCRIBE attempts completed")}
	}
	return testOutcome{Err: fmt.Errorf("skipped: DESCRIBE attempts failed (%s)", strings.Join(statuses, ", "))}
}

func testBasicChallenge(client *rtspClient, opts moduleOptions) testOutcome {
	for _, path := range opts.ProbePaths {
		uri := client.urlForPath(path)
		headers := map[string]string{"Accept": "application/sdp"}
		if err := client.sendRequest("DESCRIBE", uri, headers, ""); err != nil {
			return testOutcome{Err: err}
		}
		resp, err := client.recvResponse(defaultTimeout)
		if err != nil {
			return testOutcome{Err: err}
		}
		if resp.StatusCode == 401 {
			auth := strings.ToLower(resp.Header("www-authenticate"))
			if auth == "" {
				continue
			}
			if strings.Contains(auth, "basic") {
				desc := fmt.Sprintf("Server challenged DESCRIBE %s with Basic authentication.", uri)
				evidence := map[string]any{
					"path":             normalizeRTSPPath(path),
					"www_authenticate": resp.Header("www-authenticate"),
				}
				return testOutcome{Description: desc, Evidence: evidence}
			}
		}
	}
	return testOutcome{Err: errors.New("skipped: no Basic authentication challenge observed")}
}

func parseModuleOptions(params map[string]any) moduleOptions {
	opts := moduleOptions{
		UserAgent: defaultUserAgent,
	}
	opts.ProbePaths = append([]string(nil), defaultProbePaths...)

	if params == nil {
		opts.ProbePaths = normalizeProbePaths(opts.ProbePaths)
		return opts
	}

	if ua, ok := params["user_agent"].(string); ok && strings.TrimSpace(ua) != "" {
		opts.UserAgent = ua
	}

	if rawPaths, ok := params["probe_paths"]; ok {
		var parsed []string
		switch v := rawPaths.(type) {
		case []string:
			parsed = append(parsed, v...)
		case []any:
			for _, item := range v {
				if s, ok := item.(string); ok {
					parsed = append(parsed, s)
				}
			}
		}
		if len(parsed) > 0 {
			opts.ProbePaths = parsed
		}
	}

	opts.ProbePaths = normalizeProbePaths(opts.ProbePaths)
	if len(opts.ProbePaths) == 0 {
		opts.ProbePaths = normalizeProbePaths(defaultProbePaths)
	}
	return opts
}

type moduleOptions struct {
	ProbePaths []string
	UserAgent  string
}

type rtspClient struct {
	ctx        context.Context
	stream     cnd.Stream
	target     domain.HostPort
	seq        int
	userAgent  string
	baseHost   string
	cachePaths map[string]string
}

func newRTSPClient(ctx context.Context, stream cnd.Stream, target domain.HostPort, userAgent string) *rtspClient {
	return &rtspClient{
		ctx:        ctx,
		stream:     stream,
		target:     target,
		seq:        1,
		userAgent:  userAgent,
		baseHost:   formatRTSPHost(target.Host),
		cachePaths: make(map[string]string),
	}
}

func (c *rtspClient) urlForPath(path string) string {
	if normalized, ok := c.cachePaths[path]; ok {
		return normalized
	}
	p := normalizeRTSPPath(path)
	url := fmt.Sprintf("rtsp://%s:%d%s", c.baseHost, c.target.Port, p)
	c.cachePaths[path] = url
	return url
}

func (c *rtspClient) sendRequest(method, uri string, headers map[string]string, body string) error {
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("%s %s RTSP/1.0\r\n", method, uri))
	builder.WriteString(fmt.Sprintf("CSeq: %d\r\n", c.seq))
	c.seq++
	if c.userAgent != "" {
		builder.WriteString(fmt.Sprintf("User-Agent: %s\r\n", c.userAgent))
	}
	for k, v := range headers {
		if strings.TrimSpace(k) == "" {
			continue
		}
		builder.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	builder.WriteString("\r\n")
	if body != "" {
		builder.WriteString(body)
	}
	_, _, err := c.stream.Send(c.ctx, []byte(builder.String()), nil, nil)
	return err
}

func (c *rtspClient) recvResponse(timeout time.Duration) (*rtspResponse, error) {
	ctx := c.ctx
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(c.ctx, timeout)
		defer cancel()
	}

	var buf bytes.Buffer
	headerEnd := -1
	contentLength := -1
	for {
		chunk, err := c.stream.Recv(ctx, &cnd.RecvOptions{MaxBytes: 4096})
		if err != nil {
			return nil, err
		}
		if chunk == nil || chunk.Data == nil {
			return nil, io.EOF
		}
		data := chunk.Data.Bytes()
		buf.Write(data)
		chunk.Data.Release()

		if headerEnd == -1 {
			if idx := bytes.Index(buf.Bytes(), []byte("\r\n\r\n")); idx != -1 {
				headerEnd = idx
				headerText := string(buf.Bytes()[:headerEnd])
				contentLength = parseContentLength(headerText)
			}
		}

		if headerEnd != -1 {
			needed := headerEnd + 4
			if contentLength >= 0 {
				needed += contentLength
			}
			if buf.Len() >= needed {
				break
			}
		}
	}

	if headerEnd == -1 {
		return nil, errors.New("malformed RTSP response: missing headers")
	}

	raw := buf.Bytes()
	headerPart := raw[:headerEnd]
	body := raw[headerEnd+4:]
	if contentLength >= 0 && len(body) > contentLength {
		body = body[:contentLength]
	}

	lines := strings.Split(string(headerPart), "\r\n")
	if len(lines) == 0 {
		return nil, errors.New("malformed RTSP response: empty status line")
	}

	statusParts := strings.SplitN(lines[0], " ", 3)
	if len(statusParts) < 2 {
		return nil, fmt.Errorf("malformed RTSP status line: %s", lines[0])
	}
	code, err := strconv.Atoi(statusParts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid RTSP status code %q", statusParts[1])
	}
	statusText := ""
	if len(statusParts) > 2 {
		statusText = statusParts[2]
	}

	headers := make(map[string]string)
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])
		headers[key] = value
	}

	return &rtspResponse{
		StatusCode: code,
		StatusText: statusText,
		Headers:    headers,
		Body:       append([]byte(nil), body...),
	}, nil
}

type rtspResponse struct {
	StatusCode int
	StatusText string
	Headers    map[string]string
	Body       []byte
}

func (r *rtspResponse) Header(name string) string {
	if r == nil {
		return ""
	}
	return r.Headers[strings.ToLower(name)]
}

func parseContentLength(headerText string) int {
	lines := strings.Split(headerText, "\r\n")
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(parts[0]), "Content-Length") {
			value := strings.TrimSpace(parts[1])
			if n, err := strconv.Atoi(value); err == nil {
				return n
			}
		}
	}
	return -1
}

func normalizeProbePaths(paths []string) []string {
	seen := make(map[string]struct{})
	var normalized []string
	for _, path := range paths {
		p := normalizeRTSPPath(path)
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		normalized = append(normalized, p)
	}
	return normalized
}

func normalizeRTSPPath(path string) string {
	p := strings.TrimSpace(path)
	if p == "" || p == "*" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

func formatRTSPHost(host string) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return "[" + host + "]"
	}
	return host
}

func snippet(body string) string {
	s := strings.TrimSpace(body)
	if len(s) > 160 {
		return s[:160] + "..."
	}
	return s
}

func parsePublicHeader(value string) []string {
	var methods []string
	for _, part := range strings.Split(value, ",") {
		m := strings.TrimSpace(part)
		if m != "" {
			methods = append(methods, m)
		}
	}
	return methods
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

func buildFinding(moduleID string, target domain.Target, tc testCase, outcome testOutcome) domain.Finding {
	success := outcome.Err == nil
	severity := tc.FailureSeverity
	description := ""

	if success {
		if outcome.Description != "" {
			description = outcome.Description
		} else {
			description = "Test completed successfully."
		}
		severity = tc.SuccessSeverity
	} else if outcome.Err != nil {
		description = outcome.Err.Error()
	} else {
		description = "Test failed."
	}

	return domain.Finding{
		ID:          tc.ID,
		ModuleID:    moduleID,
		Success:     success,
		Title:       tc.Name,
		Severity:    severity,
		Description: description,
		Evidence:    outcome.Evidence,
		Tags:        tc.Tags,
		Timestamp:   time.Now().UTC(),
		Target:      target,
	}
}
