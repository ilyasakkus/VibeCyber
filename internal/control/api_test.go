package control

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/webcyber/webcyber/internal/model"
	"github.com/webcyber/webcyber/internal/scan"
)

const testToken = "test-control-token-32-bytes-minimum"

func testAPI(t *testing.T, scanner Scanner, allowLocal bool, heartbeat time.Duration) (*API, *Manager) {
	t.Helper()
	manager := testManager(t, scanner, ManagerConfig{MaxConcurrency: 1, MaxJobs: 4, MaxRetained: 10})
	api, err := NewAPI(APIConfig{
		Manager:           manager,
		Token:             testToken,
		AllowLocal:        allowLocal,
		Version:           "test-version",
		HeartbeatInterval: heartbeat,
	})
	if err != nil {
		t.Fatalf("NewAPI: %v", err)
	}
	return api, manager
}

func authorizedRequest(t *testing.T, method, target string, body io.Reader) *http.Request {
	t.Helper()
	request := httptest.NewRequest(method, target, body)
	request.Header.Set("Authorization", "Bearer "+testToken)
	return request
}

func createBody(scanType, target, profile string, authorized bool) string {
	payload, _ := json.Marshal(map[string]any{
		"type":       scanType,
		"target":     target,
		"profile":    profile,
		"authorized": authorized,
	})
	return string(payload)
}

type flushRecorder struct {
	*httptest.ResponseRecorder
	flushed chan struct{}
}

func (recorder *flushRecorder) Flush() {
	recorder.ResponseRecorder.Flush()
	recorder.flushed <- struct{}{}
}

func TestAPIRequiresBearerAuthAndSetsSecurityHeaders(t *testing.T) {
	api, _ := testAPI(t, scannerFunc(func(_ context.Context, config scan.Config) (model.Report, error) {
		return completedReport(config, "completed"), nil
	}), false, time.Second)

	request := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	request.Header.Set("Origin", "https://untrusted.example")
	recorder := httptest.NewRecorder()
	api.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d", recorder.Code)
	}
	if recorder.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("WWW-Authenticate was not set")
	}
	for header, expected := range map[string]string{
		"Cache-Control":           "no-store, max-age=0",
		"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
		"Referrer-Policy":         "no-referrer",
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
	} {
		if actual := recorder.Header().Get(header); actual != expected {
			t.Errorf("%s = %q, want %q", header, actual, expected)
		}
	}
	if origin := recorder.Header().Get("Access-Control-Allow-Origin"); origin != "" {
		t.Fatalf("unexpected CORS header %q", origin)
	}

	request = authorizedRequest(t, http.MethodGet, "/api/v1/health", nil)
	recorder = httptest.NewRecorder()
	api.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("authorized health status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var health healthResponse
	if err := json.NewDecoder(recorder.Body).Decode(&health); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	if health.Status != "ok" || health.Version != "test-version" {
		t.Fatalf("health = %#v", health)
	}
	if !health.Capabilities.Web || health.Capabilities.LocalPaths || health.Capabilities.MaxConcurrency != 1 {
		t.Fatalf("capabilities = %#v", health.Capabilities)
	}

	request = authorizedRequest(t, http.MethodOptions, "/api/v1/health", nil)
	recorder = httptest.NewRecorder()
	api.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("OPTIONS status = %d, want 405", recorder.Code)
	}
	if recorder.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("OPTIONS emitted a CORS allow-origin header")
	}
}

func TestAPIRejectsInvalidAndOversizedCreateRequests(t *testing.T) {
	api, _ := testAPI(t, scannerFunc(func(_ context.Context, config scan.Config) (model.Report, error) {
		return completedReport(config, "completed"), nil
	}), false, time.Second)

	tests := []struct {
		name        string
		contentType string
		body        string
		status      int
		code        string
	}{
		{
			name:   "missing content type",
			body:   createBody("web", "https://example.test", "observe", true),
			status: http.StatusUnsupportedMediaType,
			code:   "unsupported_media_type",
		},
		{
			name:        "authorization acknowledgement required",
			contentType: "application/json",
			body:        createBody("web", "https://example.test", "observe", false),
			status:      http.StatusBadRequest,
			code:        "authorization_required",
		},
		{
			name:        "invalid type",
			contentType: "application/json",
			body:        createBody("network", "https://example.test", "observe", true),
			status:      http.StatusBadRequest,
			code:        "invalid_type",
		},
		{
			name:        "invalid profile",
			contentType: "application/json",
			body:        createBody("web", "https://example.test", "active", true),
			status:      http.StatusBadRequest,
			code:        "invalid_profile",
		},
		{
			name:        "unknown field",
			contentType: "application/json",
			body:        `{"type":"web","target":"https://example.test","profile":"observe","authorized":true,"extra":1}`,
			status:      http.StatusBadRequest,
			code:        "invalid_json",
		},
		{
			name:        "multiple objects",
			contentType: "application/json",
			body:        createBody("web", "https://example.test", "observe", true) + `{}`,
			status:      http.StatusBadRequest,
			code:        "invalid_json",
		},
		{
			name:        "local paths disabled",
			contentType: "application/json",
			body:        createBody("source", "/tmp/project", "observe", true),
			status:      http.StatusForbidden,
			code:        "local_paths_disabled",
		},
		{
			name:        "oversized body",
			contentType: "application/json",
			body:        `{"type":"web","target":"` + strings.Repeat("a", maxRequestBodyBytes) + `","profile":"observe","authorized":true}`,
			status:      http.StatusRequestEntityTooLarge,
			code:        "body_too_large",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := authorizedRequest(t, http.MethodPost, "/api/v1/scans", strings.NewReader(test.body))
			if test.contentType != "" {
				request.Header.Set("Content-Type", test.contentType)
			}
			recorder := httptest.NewRecorder()
			api.ServeHTTP(recorder, request)
			if recorder.Code != test.status {
				t.Fatalf("status = %d, want %d; body=%s", recorder.Code, test.status, recorder.Body.String())
			}
			var envelope errorEnvelope
			if err := json.NewDecoder(recorder.Body).Decode(&envelope); err != nil {
				t.Fatalf("decode error: %v", err)
			}
			if envelope.Error.Code != test.code {
				t.Fatalf("error code = %q, want %q", envelope.Error.Code, test.code)
			}
		})
	}
}

func TestAPICreateListGetAndCancel(t *testing.T) {
	started := make(chan struct{})
	api, manager := testAPI(t, scannerFunc(func(ctx context.Context, config scan.Config) (model.Report, error) {
		close(started)
		<-ctx.Done()
		return completedReport(config, "failed"), ctx.Err()
	}), true, time.Second)

	request := authorizedRequest(t, http.MethodPost, "/api/v1/scans", strings.NewReader(createBody("source", "/tmp/project", "safe", true)))
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	recorder := httptest.NewRecorder()
	api.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("create status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var created Job
	if err := json.NewDecoder(recorder.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	if created.Status != StatusQueued || created.Type != model.ScanTypeSource {
		t.Fatalf("created job = %#v", created)
	}
	if recorder.Header().Get("Location") != "/api/v1/scans/"+created.ID {
		t.Fatalf("Location = %q", recorder.Header().Get("Location"))
	}
	<-started

	request = authorizedRequest(t, http.MethodGet, "/api/v1/scans", nil)
	recorder = httptest.NewRecorder()
	api.ServeHTTP(recorder, request)
	var listed scansResponse
	if err := json.NewDecoder(recorder.Body).Decode(&listed); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listed.Scans) != 1 || listed.Scans[0].ID != created.ID {
		t.Fatalf("list = %#v", listed)
	}

	request = authorizedRequest(t, http.MethodDelete, "/api/v1/scans/"+created.ID, nil)
	recorder = httptest.NewRecorder()
	api.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("cancel status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var cancelled Job
	if err := json.NewDecoder(recorder.Body).Decode(&cancelled); err != nil {
		t.Fatalf("decode cancel: %v", err)
	}
	if cancelled.Status != StatusCancelling || cancelled.FinishedAt != nil {
		t.Fatalf("cancelled job = %#v", cancelled)
	}
	waitForStatus(t, manager, created.ID, StatusCancelled)

	request = authorizedRequest(t, http.MethodGet, "/api/v1/scans/"+created.ID, nil)
	recorder = httptest.NewRecorder()
	api.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("get status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var fetched Job
	if err := json.NewDecoder(recorder.Body).Decode(&fetched); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	if fetched.Status != StatusCancelled {
		t.Fatalf("fetched status = %s", fetched.Status)
	}
	if fetched.FinishedAt == nil || fetched.Report == nil || fetched.Report.Scan.ID != fetched.ID {
		t.Fatalf("fetched terminal job = %#v", fetched)
	}

	request = authorizedRequest(t, http.MethodGet, "/api/v1/scans/not-found", nil)
	recorder = httptest.NewRecorder()
	api.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("missing scan status = %d", recorder.Code)
	}
}

func TestAPIKeepsRawWebTargetOutOfAllPublicResponses(t *testing.T) {
	raw := "https://alice:user-secret@example.test/private/path?api_key=query-secret#fragment-secret"
	received := make(chan string, 1)
	api, manager := testAPI(t, scannerFunc(func(_ context.Context, config scan.Config) (model.Report, error) {
		received <- config.Target
		return completedReport(config, "completed"), nil
	}), false, time.Second)

	request := authorizedRequest(t, http.MethodPost, "/api/v1/scans", strings.NewReader(createBody("web", raw, "observe", true)))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	api.ServeHTTP(recorder, request)
	createPayload := append([]byte(nil), recorder.Body.Bytes()...)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("create status = %d, body=%s", recorder.Code, createPayload)
	}
	var created Job
	if err := json.Unmarshal(createPayload, &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	if created.Target != "https://example.test/private/path" {
		t.Fatalf("created target = %q", created.Target)
	}
	if scanned := <-received; scanned != raw {
		t.Fatalf("scanner received %q, want raw private target", scanned)
	}
	waitForStatus(t, manager, created.ID, StatusCompleted)

	request = authorizedRequest(t, http.MethodGet, "/api/v1/scans", nil)
	recorder = httptest.NewRecorder()
	api.ServeHTTP(recorder, request)
	listPayload := append([]byte(nil), recorder.Body.Bytes()...)

	request = authorizedRequest(t, http.MethodGet, "/api/v1/scans/"+created.ID, nil)
	recorder = httptest.NewRecorder()
	api.ServeHTTP(recorder, request)
	detailPayload := append([]byte(nil), recorder.Body.Bytes()...)
	var detail Job
	if err := json.Unmarshal(detailPayload, &detail); err != nil {
		t.Fatalf("decode detail: %v", err)
	}
	if detail.Report == nil ||
		detail.Report.Scan.ID != detail.ID ||
		detail.Report.Scan.Target != detail.Target {
		t.Fatalf("detail identity = %#v", detail)
	}

	for name, payload := range map[string][]byte{
		"create": createPayload,
		"list":   listPayload,
		"detail": detailPayload,
	} {
		for _, secret := range []string{"alice", "user-secret", "api_key", "query-secret", "fragment-secret"} {
			if bytes.Contains(payload, []byte(secret)) {
				t.Errorf("%s response leaked %q: %s", name, secret, payload)
			}
		}
	}
}

func TestAPICancelAllReturnsChangedJobs(t *testing.T) {
	started := make(chan struct{})
	api, _ := testAPI(t, scannerFunc(func(ctx context.Context, config scan.Config) (model.Report, error) {
		close(started)
		<-ctx.Done()
		return completedReport(config, "failed"), ctx.Err()
	}), true, time.Second)

	for _, target := range []string{"one", "two"} {
		request := authorizedRequest(t, http.MethodPost, "/api/v1/scans", strings.NewReader(createBody("web", target, "observe", true)))
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		api.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusAccepted {
			t.Fatalf("create %q status = %d", target, recorder.Code)
		}
		if target == "one" {
			<-started
		}
	}

	request := authorizedRequest(t, http.MethodDelete, "/api/v1/scans", nil)
	recorder := httptest.NewRecorder()
	api.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("cancel all status = %d", recorder.Code)
	}
	var response scansResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode cancel all: %v", err)
	}
	if len(response.Scans) != 2 {
		t.Fatalf("cancel all changed %d jobs", len(response.Scans))
	}
}

func TestAPICancelKeepsSSEOpenUntilWorkerActuallyStops(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	api, manager := testAPI(t, scannerFunc(func(_ context.Context, config scan.Config) (model.Report, error) {
		close(started)
		<-release
		return completedReport(config, "completed"), nil
	}), false, time.Hour)
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })

	job, err := manager.Submit(testScanConfig("https://example.test/path?token=secret"))
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	<-started
	waitForStatus(t, manager, job.ID, StatusRunning)

	streamRequest := authorizedRequest(t, http.MethodGet, "/api/v1/scans/"+job.ID+"/events", nil)
	streamRecorder := &flushRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		flushed:          make(chan struct{}, 8),
	}
	streamDone := make(chan struct{})
	go func() {
		api.ServeHTTP(streamRecorder, streamRequest)
		close(streamDone)
	}()
	select {
	case <-streamRecorder.flushed:
	case <-time.After(time.Second):
		t.Fatal("initial SSE state was not flushed")
	}

	request := authorizedRequest(t, http.MethodDelete, "/api/v1/scans/"+job.ID, nil)
	recorder := httptest.NewRecorder()
	api.ServeHTTP(recorder, request)
	var cancelling Job
	if err := json.NewDecoder(recorder.Body).Decode(&cancelling); err != nil {
		t.Fatalf("decode cancelling response: %v", err)
	}
	if cancelling.Status != StatusCancelling || cancelling.FinishedAt != nil {
		t.Fatalf("cancelling response = %#v", cancelling)
	}
	select {
	case <-streamRecorder.flushed:
	case <-time.After(time.Second):
		t.Fatal("cancelling SSE state was not flushed")
	}
	select {
	case <-streamDone:
		t.Fatal("SSE stream closed while scanner was still running")
	case <-time.After(20 * time.Millisecond):
	}

	request = authorizedRequest(t, http.MethodDelete, "/api/v1/scans/"+job.ID, nil)
	recorder = httptest.NewRecorder()
	api.ServeHTTP(recorder, request)
	var repeated Job
	if err := json.NewDecoder(recorder.Body).Decode(&repeated); err != nil {
		t.Fatalf("decode repeated cancel: %v", err)
	}
	if repeated.Status != StatusCancelling || repeated.FinishedAt != nil {
		t.Fatalf("repeated cancellation response = %#v", repeated)
	}

	releaseOnce.Do(func() { close(release) })
	select {
	case <-streamDone:
	case <-time.After(time.Second):
		t.Fatal("SSE stream did not close after worker exit")
	}
	streamBody := streamRecorder.Body.String()
	cancellingIndex := strings.Index(streamBody, "event: cancelling\n")
	cancelledIndex := strings.Index(streamBody, "event: cancelled\n")
	if cancellingIndex < 0 || cancelledIndex <= cancellingIndex {
		t.Fatalf("unexpected cancellation SSE order: %q", streamBody)
	}

	cancelled := waitForStatus(t, manager, job.ID, StatusCancelled)
	if cancelled.FinishedAt == nil || cancelled.Report == nil {
		t.Fatalf("terminal cancelled job = %#v", cancelled)
	}
	if cancelled.Report.Scan.ID != cancelled.ID ||
		cancelled.Report.Scan.Target != cancelled.Target ||
		cancelled.Report.Scan.Status != string(StatusCancelled) {
		t.Fatalf("terminal report identity = %#v", cancelled.Report.Scan)
	}
}

func TestAPIListOmitsReportsWhileGetReturnsFullReport(t *testing.T) {
	api, manager := testAPI(t, scannerFunc(func(_ context.Context, config scan.Config) (model.Report, error) {
		report := completedReport(config, "completed")
		report.Findings = []model.Finding{{
			RuleID:      "test.rule",
			Fingerprint: "sha256:test",
			Module:      "test",
			Title:       "Test finding",
			Severity:    model.SeverityHigh,
			Description: "Only the detail endpoint should carry this finding.",
		}}
		return report, nil
	}), false, time.Second)

	job, err := manager.Submit(testScanConfig("https://example.test"))
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	waitForStatus(t, manager, job.ID, StatusCompleted)

	request := authorizedRequest(t, http.MethodGet, "/api/v1/scans", nil)
	recorder := httptest.NewRecorder()
	api.ServeHTTP(recorder, request)
	listPayload := append([]byte(nil), recorder.Body.Bytes()...)
	var list scansResponse
	if err := json.Unmarshal(listPayload, &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list.Scans) != 1 || list.Scans[0].Report != nil {
		t.Fatalf("list unexpectedly contains a report: %#v", list.Scans)
	}
	if bytes.Contains(listPayload, []byte(`"report"`)) {
		t.Fatalf("list JSON contains report field: %s", listPayload)
	}

	request = authorizedRequest(t, http.MethodGet, "/api/v1/scans/"+job.ID, nil)
	recorder = httptest.NewRecorder()
	api.ServeHTTP(recorder, request)
	var detail Job
	if err := json.NewDecoder(recorder.Body).Decode(&detail); err != nil {
		t.Fatalf("decode detail: %v", err)
	}
	if detail.Report == nil || len(detail.Report.Findings) != 1 {
		t.Fatalf("detail report = %#v", detail.Report)
	}
}

func TestAPISSEStreamsCurrentHeartbeatAndTerminalState(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	api, _ := testAPI(t, scannerFunc(func(ctx context.Context, config scan.Config) (model.Report, error) {
		close(started)
		select {
		case <-release:
			return completedReport(config, "completed"), nil
		case <-ctx.Done():
			return completedReport(config, "failed"), ctx.Err()
		}
	}), false, 10*time.Millisecond)

	body := createBody("web", "https://example.test", "observe", true)
	request := authorizedRequest(t, http.MethodPost, "/api/v1/scans", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	api.ServeHTTP(recorder, request)
	var job Job
	if err := json.NewDecoder(recorder.Body).Decode(&job); err != nil {
		t.Fatalf("decode job: %v", err)
	}
	<-started

	request = authorizedRequest(t, http.MethodGet, "/api/v1/scans/"+job.ID+"/events", nil)
	streamRecorder := &flushRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		flushed:          make(chan struct{}, 8),
	}
	streamDone := make(chan struct{})
	go func() {
		api.ServeHTTP(streamRecorder, request)
		close(streamDone)
	}()
	for flush := 0; flush < 2; flush++ {
		select {
		case <-streamRecorder.flushed:
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for SSE flush %d", flush+1)
		}
	}
	close(release)
	select {
	case <-streamDone:
	case <-time.After(2 * time.Second):
		t.Fatal("SSE handler did not finish after terminal event")
	}
	if streamRecorder.Code != http.StatusOK {
		t.Fatalf("events status = %d, body=%s", streamRecorder.Code, streamRecorder.Body.String())
	}
	if contentType := streamRecorder.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/event-stream") {
		t.Fatalf("events Content-Type = %q", contentType)
	}

	streamBody := streamRecorder.Body.Bytes()
	for _, expected := range [][]byte{
		[]byte("event: queued\n"),
		[]byte("event: running\n"),
		[]byte(": heartbeat\n\n"),
		[]byte("event: completed\n"),
		[]byte(`"status":"completed"`),
	} {
		if !bytes.Contains(streamBody, expected) {
			t.Fatalf("SSE body does not contain %q: %q", expected, streamBody)
		}
	}

	request = authorizedRequest(t, http.MethodGet, "/api/v1/scans/"+job.ID, nil)
	recorder = httptest.NewRecorder()
	api.ServeHTTP(recorder, request)
	var completed Job
	if err := json.NewDecoder(recorder.Body).Decode(&completed); err != nil {
		t.Fatalf("decode completed job: %v", err)
	}
	if completed.Status != StatusCompleted || completed.Report == nil {
		t.Fatalf("completed job = %#v", completed)
	}
}

func TestNewAPIRejectsEmptyToken(t *testing.T) {
	manager := testManager(t, scannerFunc(func(context.Context, scan.Config) (model.Report, error) {
		return model.Report{}, nil
	}), testConfig())
	if _, err := NewAPI(APIConfig{Manager: manager, Token: " \t "}); err == nil {
		t.Fatal("NewAPI accepted a whitespace token")
	}
}

func TestValidBearer(t *testing.T) {
	for header, valid := range map[string]bool{
		"Bearer expected-control-token":       true,
		"bearer expected-control-token":       true,
		"Basic expected-control-token":        false,
		"Bearer wrong":                        false,
		"Bearer expected-control-token extra": false,
		"":                                    false,
	} {
		if actual := validBearer(header, "expected-control-token"); actual != valid {
			t.Errorf("validBearer(%q) = %v, want %v", header, actual, valid)
		}
	}
}
