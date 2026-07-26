package control

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/webcyber/webcyber/internal/model"
	"github.com/webcyber/webcyber/internal/scan"
)

const (
	maxRequestBodyBytes = 64 << 10
	defaultHeartbeat    = 15 * time.Second
)

var jobIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// APIConfig configures the authenticated HTTP boundary.
type APIConfig struct {
	Manager           *Manager
	Token             string
	AllowLocal        bool
	Version           string
	HeartbeatInterval time.Duration
}

// API is an http.Handler for the versioned control endpoints.
type API struct {
	manager    *Manager
	token      string
	allowLocal bool
	version    string
	heartbeat  time.Duration
	handler    http.Handler
}

// NewAPI creates an authenticated API. A minimum token size is enforced so a
// deployment cannot accidentally expose the scanner with a weak secret.
func NewAPI(config APIConfig) (*API, error) {
	if config.Manager == nil {
		return nil, errors.New("manager must not be nil")
	}
	config.Token = strings.TrimSpace(config.Token)
	if len(config.Token) < 32 {
		return nil, errors.New("control token must contain at least 32 bytes")
	}
	if len(strings.Fields(config.Token)) != 1 {
		return nil, errors.New("control token must not contain whitespace")
	}
	if config.Version == "" {
		config.Version = scan.Version
	}
	if config.HeartbeatInterval <= 0 {
		config.HeartbeatInterval = defaultHeartbeat
	}
	api := &API{
		manager:    config.Manager,
		token:      config.Token,
		allowLocal: config.AllowLocal,
		version:    config.Version,
		heartbeat:  config.HeartbeatInterval,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", api.health)
	mux.HandleFunc("GET /api/v1/scans", api.listScans)
	mux.HandleFunc("POST /api/v1/scans", api.createScan)
	mux.HandleFunc("DELETE /api/v1/scans", api.cancelAllScans)
	mux.HandleFunc("GET /api/v1/scans/{id}", api.getScan)
	mux.HandleFunc("DELETE /api/v1/scans/{id}", api.cancelScan)
	mux.HandleFunc("GET /api/v1/scans/{id}/events", api.scanEvents)
	api.handler = api.securityHeaders(api.authenticate(mux))
	return api, nil
}

func (a *API) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	a.handler.ServeHTTP(writer, request)
}

type capabilities struct {
	Web            bool `json:"web"`
	Source         bool `json:"source"`
	Mobile         bool `json:"mobile"`
	Desktop        bool `json:"desktop"`
	LocalPaths     bool `json:"localPaths"`
	MaxConcurrency int  `json:"maxConcurrency"`
}

type healthResponse struct {
	Status       string       `json:"status"`
	Version      string       `json:"version"`
	Capabilities capabilities `json:"capabilities"`
}

type scansResponse struct {
	Scans []Job `json:"scans"`
}

type createScanRequest struct {
	Type       model.ScanType `json:"type"`
	Target     string         `json:"target"`
	Profile    model.Profile  `json:"profile"`
	Authorized bool           `json:"authorized"`
}

func (a *API) health(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, healthResponse{
		Status:  "ok",
		Version: a.version,
		Capabilities: capabilities{
			Web:            true,
			Source:         true,
			Mobile:         true,
			Desktop:        true,
			LocalPaths:     a.allowLocal,
			MaxConcurrency: a.manager.MaxConcurrency(),
		},
	})
}

func (a *API) listScans(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, scansResponse{Scans: a.manager.List()})
}

func (a *API) createScan(writer http.ResponseWriter, request *http.Request) {
	var input createScanRequest
	if err := decodeJSON(writer, request, &input); err != nil {
		switch {
		case errors.Is(err, errUnsupportedMediaType):
			writeError(writer, http.StatusUnsupportedMediaType, "unsupported_media_type", err.Error())
		case errors.Is(err, errBodyTooLarge):
			writeError(writer, http.StatusRequestEntityTooLarge, "body_too_large", err.Error())
		default:
			writeError(writer, http.StatusBadRequest, "invalid_json", err.Error())
		}
		return
	}
	input.Target = strings.TrimSpace(input.Target)
	if !input.Authorized {
		writeError(writer, http.StatusBadRequest, "authorization_required", "authorized must be true before a scan can start")
		return
	}
	if !input.Type.Valid() {
		writeError(writer, http.StatusBadRequest, "invalid_type", "type must be one of web, source, mobile, or desktop")
		return
	}
	if !input.Profile.Valid() {
		writeError(writer, http.StatusBadRequest, "invalid_profile", "profile must be observe or safe")
		return
	}
	if input.Target == "" {
		writeError(writer, http.StatusBadRequest, "invalid_target", "target must not be empty")
		return
	}
	if len(input.Target) > 4096 {
		writeError(writer, http.StatusBadRequest, "invalid_target", "target exceeds the 4096 byte limit")
		return
	}
	if input.Type != model.ScanTypeWeb && !a.allowLocal {
		writeError(writer, http.StatusForbidden, "local_paths_disabled", "local path scans are disabled by this control service")
		return
	}

	job, err := a.manager.Submit(scan.Config{
		Type:    input.Type,
		Target:  input.Target,
		Profile: input.Profile,
	})
	switch {
	case err == nil:
		writer.Header().Set("Location", "/api/v1/scans/"+job.ID)
		writeJSON(writer, http.StatusAccepted, job)
	case errors.Is(err, ErrQueueFull):
		writer.Header().Set("Retry-After", "1")
		writeError(writer, http.StatusTooManyRequests, "queue_full", "the bounded scan queue is full")
	case errors.Is(err, ErrClosed):
		writeError(writer, http.StatusServiceUnavailable, "shutting_down", "the scan service is shutting down")
	default:
		writeError(writer, http.StatusInternalServerError, "internal_error", "the scan could not be queued")
	}
}

func (a *API) getScan(writer http.ResponseWriter, request *http.Request) {
	id, ok := scanID(writer, request)
	if !ok {
		return
	}
	job, err := a.manager.Get(id)
	if errors.Is(err, ErrNotFound) {
		writeError(writer, http.StatusNotFound, "not_found", "scan job was not found")
		return
	}
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "internal_error", "scan job could not be read")
		return
	}
	writeJSON(writer, http.StatusOK, job)
}

func (a *API) cancelScan(writer http.ResponseWriter, request *http.Request) {
	id, ok := scanID(writer, request)
	if !ok {
		return
	}
	job, err := a.manager.Cancel(id)
	if errors.Is(err, ErrNotFound) {
		writeError(writer, http.StatusNotFound, "not_found", "scan job was not found")
		return
	}
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "internal_error", "scan job could not be cancelled")
		return
	}
	writeJSON(writer, http.StatusOK, job)
}

func (a *API) cancelAllScans(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, scansResponse{Scans: a.manager.CancelAll()})
}

func (a *API) scanEvents(writer http.ResponseWriter, request *http.Request) {
	id, ok := scanID(writer, request)
	if !ok {
		return
	}
	subscription, err := a.manager.Subscribe(id)
	if errors.Is(err, ErrNotFound) {
		writeError(writer, http.StatusNotFound, "not_found", "scan job was not found")
		return
	}
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "internal_error", "scan events could not be opened")
		return
	}
	defer subscription.Close()

	flusher, ok := writer.(http.Flusher)
	if !ok {
		writeError(writer, http.StatusInternalServerError, "streaming_unsupported", "streaming is not supported by this server")
		return
	}

	writer.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-cache, no-store, max-age=0")
	writer.Header().Set("X-Accel-Buffering", "no")
	writer.WriteHeader(http.StatusOK)
	initialEvents := []Event{{
		ID:        subscription.Current.ID,
		Status:    StatusQueued,
		Timestamp: subscription.Current.CreatedAt,
	}}
	if subscription.Current.StartedAt != nil {
		initialEvents = append(initialEvents, Event{
			ID:        subscription.Current.ID,
			Status:    StatusRunning,
			Timestamp: *subscription.Current.StartedAt,
		})
	}
	if subscription.Current.Status == StatusCancelling {
		initialEvents = append(initialEvents, Event{
			ID:        subscription.Current.ID,
			Status:    StatusCancelling,
			Timestamp: time.Now().UTC(),
		})
	}
	if terminal(subscription.Current.Status) {
		timestamp := time.Now().UTC()
		if subscription.Current.FinishedAt != nil {
			timestamp = *subscription.Current.FinishedAt
		}
		initialEvents = append(initialEvents, Event{
			ID:        subscription.Current.ID,
			Status:    subscription.Current.Status,
			Timestamp: timestamp,
		})
	}
	for _, event := range initialEvents {
		if err := writeSSE(writer, event); err != nil {
			return
		}
	}
	flusher.Flush()
	if terminal(subscription.Current.Status) {
		return
	}

	heartbeat := time.NewTicker(a.heartbeat)
	defer heartbeat.Stop()
	for {
		select {
		case <-request.Context().Done():
			return
		case event, open := <-subscription.Events:
			if !open {
				return
			}
			if err := writeSSE(writer, event); err != nil {
				return
			}
			flusher.Flush()
			if terminal(event.Status) {
				return
			}
		case <-heartbeat.C:
			if _, err := io.WriteString(writer, ": heartbeat\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (a *API) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		values := request.Header.Values("Authorization")
		if len(values) != 1 || !validBearer(values[0], a.token) {
			writer.Header().Set("WWW-Authenticate", `Bearer realm="webcyber-control"`)
			writeError(writer, http.StatusUnauthorized, "unauthorized", "a valid bearer token is required")
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func (a *API) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store, max-age=0")
		writer.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		writer.Header().Set("Permissions-Policy", "camera=(), geolocation=(), microphone=()")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(writer, request)
	})
}

func validBearer(header, expected string) bool {
	fields := strings.Fields(header)
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") {
		return false
	}
	if len(fields[1]) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(fields[1]), []byte(expected)) == 1
}

func scanID(writer http.ResponseWriter, request *http.Request) (string, bool) {
	id := request.PathValue("id")
	if !jobIDPattern.MatchString(id) {
		writeError(writer, http.StatusBadRequest, "invalid_id", "scan job identifier is invalid")
		return "", false
	}
	return id, true
}

var (
	errUnsupportedMediaType = errors.New("content type must be application/json")
	errBodyTooLarge         = errors.New("request body exceeds the 65536 byte limit")
)

func decodeJSON(writer http.ResponseWriter, request *http.Request, destination any) error {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errUnsupportedMediaType
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maxRequestBodyBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			return errBodyTooLarge
		}
		return fmt.Errorf("request body must contain one valid JSON object: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			return errBodyTooLarge
		}
		return errors.New("request body must contain exactly one JSON object")
	}
	return nil
}

type errorEnvelope struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeError(writer http.ResponseWriter, status int, code, message string) {
	writeJSON(writer, status, errorEnvelope{Error: apiError{Code: code, Message: message}})
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func writeSSE(writer io.Writer, event Event) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "event: %s\n", event.Status); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "data: %s\n\n", payload); err != nil {
		return err
	}
	return nil
}
