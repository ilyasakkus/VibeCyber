package scan

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/webcyber/webcyber/internal/model"
)

func (e *Engine) scanWeb(ctx context.Context, cfg Config, report *model.Report) error {
	report.Scan.Target = "[invalid web URL]"
	target, err := url.Parse(cfg.Target)
	if err != nil {
		report.Modules = append(report.Modules, model.ModuleResult{Name: "target-validation", Status: model.ModuleError, Summary: "The URL could not be parsed.", Errors: []string{"invalid URL syntax"}})
		return errors.New("parse web target: invalid URL syntax")
	}
	report.Scan.Target = safeURL(target)
	guard := newSSRFGuard(e.limits.DialTimeout)
	if err := guard.validateURL(ctx, target); err != nil {
		report.Modules = append(report.Modules, model.ModuleResult{Name: "target-validation", Status: model.ModuleError, Summary: "The URL did not pass SSRF validation.", Errors: []string{err.Error()}})
		return fmt.Errorf("unsafe web target: %w", err)
	}

	client, transport := newSafeHTTPClient(guard, e.limits)
	defer transport.CloseIdleConnections()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return errors.New("create observation request: invalid target URL")
	}
	request.Header.Set("User-Agent", "WebCyber/"+Version+" (+read-only-security-observation)")
	request.Header.Set("Accept", "text/html,application/xhtml+xml,application/json;q=0.8,*/*;q=0.1")
	response, err := client.Do(request)
	if err != nil {
		safeErr := sanitizeNetworkError(err)
		report.Modules = append(report.Modules, model.ModuleResult{Name: "http-observation", Status: model.ModuleError, Summary: "The read-only HTTP observation failed.", Errors: []string{safeErr.Error()}})
		return fmt.Errorf("observe web target: %w", safeErr)
	}
	defer response.Body.Close()
	read, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, e.limits.MaxHTTPBodyBytes+1))
	if readErr != nil {
		report.Modules = append(report.Modules, model.ModuleResult{Name: "http-observation", Status: model.ModulePartial, Summary: "HTTP metadata was collected, but the response body could not be consumed safely.", Errors: []string{readErr.Error()}})
	} else {
		status := model.ModuleComplete
		limitations := []string(nil)
		if read > e.limits.MaxHTTPBodyBytes {
			status = model.ModulePartial
			limitations = append(limitations, fmt.Sprintf("Response body inspection stopped at %d bytes.", e.limits.MaxHTTPBodyBytes))
		}
		report.Modules = append(report.Modules, model.ModuleResult{
			Name:        "http-observation",
			Status:      status,
			Summary:     fmt.Sprintf("Observed HTTP %d from %s using one GET request.", response.StatusCode, safeURL(response.Request.URL)),
			ItemsSeen:   1,
			Limitations: limitations,
		})
	}

	report.Modules = append(report.Modules, inspectSecurityHeaders(response, report)...)
	inspectTLS(response, report)
	report.Limitations = append(report.Limitations,
		"The built-in web MVP performs one read-only HTTP observation; it does not crawl, fuzz, submit forms, or execute proof-of-concept payloads.",
		"Both observe and safe profiles are passive in this MVP; active checks require explicit future opt-in and isolation.",
	)
	return nil
}

func newSafeHTTPClient(guard *ssrfGuard, limits Limits) (*http.Client, *http.Transport) {
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            guard.dialContext,
		DisableCompression:     true,
		ForceAttemptHTTP2:      true,
		TLSHandshakeTimeout:    limits.DialTimeout,
		ResponseHeaderTimeout:  limits.HTTPTimeout,
		MaxResponseHeaderBytes: 1 << 20,
		MaxIdleConns:           2,
		MaxConnsPerHost:        2,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS10,
		},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   limits.HTTPTimeout,
	}
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) > limits.MaxRedirects {
			return fmt.Errorf("redirect limit of %d exceeded", limits.MaxRedirects)
		}
		if len(via) > 0 && via[len(via)-1].URL.Scheme == "https" && request.URL.Scheme == "http" {
			return fmt.Errorf("HTTPS-to-HTTP redirect is blocked")
		}
		if err := guard.validateURL(request.Context(), request.URL); err != nil {
			return fmt.Errorf("unsafe redirect target: %w", err)
		}
		return nil
	}
	return client, transport
}

func inspectSecurityHeaders(response *http.Response, report *model.Report) []model.ModuleResult {
	finalURL := safeURL(response.Request.URL)
	type requirement struct {
		name, rule, title, description, remediation string
		severity                                    model.Severity
		onHTTPS                                     bool
		browserOnly                                 bool
	}
	contentType := strings.ToLower(response.Header.Get("Content-Type"))
	browserDocument := contentType == "" || strings.Contains(contentType, "text/html") || strings.Contains(contentType, "application/xhtml+xml")
	requirements := []requirement{
		{"Content-Security-Policy", "web.header.csp.missing", "Content Security Policy is missing", "The response does not declare a Content-Security-Policy header.", "Deploy a restrictive, application-specific CSP and avoid unsafe inline/script sources.", model.SeverityMedium, false, true},
		{"X-Content-Type-Options", "web.header.nosniff.missing", "MIME sniffing protection is missing", "The response does not set X-Content-Type-Options: nosniff.", "Set X-Content-Type-Options to nosniff.", model.SeverityLow, false, false},
		{"Referrer-Policy", "web.header.referrer-policy.missing", "Referrer policy is missing", "The response does not define how referrer information is shared.", "Set an appropriate Referrer-Policy such as strict-origin-when-cross-origin.", model.SeverityLow, false, true},
		{"Permissions-Policy", "web.header.permissions-policy.missing", "Permissions Policy is missing", "Browser feature access is not constrained with a Permissions-Policy header.", "Declare only the browser features and origins the application needs.", model.SeverityLow, false, true},
		{"Strict-Transport-Security", "web.header.hsts.missing", "HTTP Strict Transport Security is missing", "An HTTPS response did not include Strict-Transport-Security.", "Set HSTS after confirming all intended subdomains support HTTPS.", model.SeverityMedium, true, false},
	}
	for _, required := range requirements {
		if required.onHTTPS && response.Request.URL.Scheme != "https" {
			continue
		}
		if required.browserOnly && !browserDocument {
			continue
		}
		if strings.TrimSpace(response.Header.Get(required.name)) == "" {
			appendFinding(report, model.Finding{
				RuleID: required.rule, Module: "security-headers", Title: required.title,
				Severity: required.severity, Confidence: "high", Description: required.description,
				Remediation: required.remediation, Evidence: model.Evidence{URL: finalURL, Details: map[string]string{"header": required.name}},
			})
		}
	}
	if browserDocument && response.Header.Get("X-Frame-Options") == "" && !strings.Contains(strings.ToLower(response.Header.Get("Content-Security-Policy")), "frame-ancestors") {
		appendFinding(report, model.Finding{
			RuleID: "web.header.clickjacking-protection.missing", Module: "security-headers", Title: "Clickjacking protection is missing",
			Severity: model.SeverityMedium, Confidence: "high", CWE: "CWE-1021",
			Description: "Neither X-Frame-Options nor a CSP frame-ancestors directive was observed.",
			Remediation: "Set CSP frame-ancestors (preferred) or X-Frame-Options to restrict framing.", Evidence: model.Evidence{URL: finalURL},
		})
	}
	if value := strings.TrimSpace(response.Header.Get("X-Content-Type-Options")); value != "" && !strings.EqualFold(value, "nosniff") {
		appendFinding(report, model.Finding{
			RuleID: "web.header.nosniff.invalid", Module: "security-headers", Title: "MIME sniffing header has an invalid value", Severity: model.SeverityLow, Confidence: "high",
			Description: "X-Content-Type-Options is present but is not set to nosniff.", Remediation: "Set X-Content-Type-Options exactly to nosniff.",
			Evidence: model.Evidence{URL: finalURL, Details: map[string]string{"header": "X-Content-Type-Options"}},
		})
	}
	if browserDocument && strings.Contains(strings.ToLower(response.Header.Get("Content-Security-Policy")), "'unsafe-eval'") {
		appendFinding(report, model.Finding{
			RuleID: "web.header.csp.unsafe-eval", Module: "security-headers", Title: "Content Security Policy allows unsafe-eval", Severity: model.SeverityMedium, Confidence: "high", CWE: "CWE-693",
			Description: "The observed CSP contains the unsafe-eval source expression.", Remediation: "Remove eval-like code paths and the unsafe-eval source expression.",
			Evidence: model.Evidence{URL: finalURL, Details: map[string]string{"header": "Content-Security-Policy"}},
		})
	}
	if response.Request.URL.Scheme == "https" {
		if hsts := strings.TrimSpace(response.Header.Get("Strict-Transport-Security")); hsts != "" {
			maxAge, ok := numericDirective(hsts, "max-age")
			if !ok || maxAge < 15_552_000 {
				detail := "invalid"
				if ok {
					detail = strconv.FormatInt(maxAge, 10)
				}
				appendFinding(report, model.Finding{
					RuleID: "web.header.hsts.weak-max-age", Module: "security-headers", Title: "HSTS max-age is missing or too short", Severity: model.SeverityMedium, Confidence: "high", CWE: "CWE-319",
					Description: "The HSTS policy does not retain HTTPS enforcement for at least 180 days.", Remediation: "After validating HTTPS coverage, deploy HSTS with a max-age of at least 15552000 seconds.",
					Evidence: model.Evidence{URL: finalURL, Details: map[string]string{"header": "Strict-Transport-Security", "max_age": detail}},
				})
			}
		}
	}
	inspectCookies(response, report)
	for _, header := range []string{"Server", "X-Powered-By"} {
		if response.Header.Get(header) != "" {
			appendFinding(report, model.Finding{
				RuleID: "web.header.technology-disclosure", Module: "security-headers", Title: "Technology information is disclosed",
				Severity: model.SeverityInfo, Confidence: "medium", Description: "A response header may reveal implementation details that help fingerprint the service.",
				Remediation: "Remove unnecessary version and technology disclosure headers.", Evidence: model.Evidence{URL: finalURL, Details: map[string]string{"header": header}},
			})
		}
	}
	return []model.ModuleResult{{Name: "security-headers", Status: model.ModuleComplete, Summary: "Evaluated defensive response headers and cookie attributes.", ItemsSeen: len(response.Header)}}
}

func inspectCookies(response *http.Response, report *model.Report) {
	for _, raw := range response.Header.Values("Set-Cookie") {
		parts := strings.Split(raw, ";")
		name := strings.TrimSpace(strings.SplitN(parts[0], "=", 2)[0])
		attributes := make(map[string]string)
		for _, rawAttribute := range parts[1:] {
			pair := strings.SplitN(strings.TrimSpace(rawAttribute), "=", 2)
			key := strings.ToLower(pair[0])
			value := ""
			if len(pair) == 2 {
				value = strings.ToLower(strings.TrimSpace(pair[1]))
			}
			attributes[key] = value
		}
		checks := []struct {
			missing, rule, title string
			severity             model.Severity
		}{
			{"httponly", "web.cookie.httponly.missing", "Cookie is missing HttpOnly", model.SeverityMedium},
			{"samesite", "web.cookie.samesite.missing", "Cookie is missing SameSite", model.SeverityLow},
		}
		checks = append(checks, struct {
			missing, rule, title string
			severity             model.Severity
		}{"secure", "web.cookie.secure.missing", "Cookie is missing Secure", model.SeverityMedium})
		for _, check := range checks {
			if _, present := attributes[check.missing]; !present {
				appendFinding(report, model.Finding{
					RuleID: check.rule, Module: "security-headers", Title: check.title, Severity: check.severity, Confidence: "high",
					Description: "A Set-Cookie header did not include the expected defensive attribute.", Remediation: "Apply appropriate Secure, HttpOnly, and SameSite attributes to sensitive cookies.",
					Evidence: model.Evidence{URL: safeURL(response.Request.URL), Details: map[string]string{"cookie_name": truncate(name, 80)}},
				})
			}
		}
	}
}

func numericDirective(header, wanted string) (int64, bool) {
	for _, directive := range strings.Split(header, ";") {
		pair := strings.SplitN(strings.TrimSpace(directive), "=", 2)
		if len(pair) != 2 || !strings.EqualFold(strings.TrimSpace(pair[0]), wanted) {
			continue
		}
		value, err := strconv.ParseInt(strings.TrimSpace(pair[1]), 10, 64)
		return value, err == nil && value >= 0
	}
	return 0, false
}

func inspectTLS(response *http.Response, report *model.Report) {
	if response.Request.URL.Scheme != "https" {
		report.Modules = append(report.Modules, model.ModuleResult{Name: "tls", Status: model.ModuleSkipped, Summary: "TLS checks do not apply to an HTTP target."})
		appendFinding(report, model.Finding{
			RuleID: "web.transport.http", Module: "tls", Title: "Target uses unencrypted HTTP", Severity: model.SeverityHigh, Confidence: "high", CWE: "CWE-319",
			Description: "The observed target URL uses HTTP, so data in transit is not protected by TLS.", Remediation: "Serve the application over HTTPS and redirect HTTP traffic to HTTPS.", Evidence: model.Evidence{URL: safeURL(response.Request.URL)},
		})
		return
	}
	if response.TLS == nil {
		report.Modules = append(report.Modules, model.ModuleResult{Name: "tls", Status: model.ModulePartial, Summary: "HTTPS was requested but TLS connection metadata was unavailable."})
		return
	}
	state := response.TLS
	report.Modules = append(report.Modules, model.ModuleResult{Name: "tls", Status: model.ModuleComplete, Summary: fmt.Sprintf("Observed %s with cipher suite 0x%04x.", tlsVersionName(state.Version), state.CipherSuite), ItemsSeen: len(state.PeerCertificates)})
	if state.Version < tls.VersionTLS12 {
		appendFinding(report, model.Finding{
			RuleID: "web.tls.legacy-version", Module: "tls", Title: "Legacy TLS version negotiated", Severity: model.SeverityHigh, Confidence: "high", CWE: "CWE-326",
			Description: "The connection negotiated a TLS version older than TLS 1.2.", Remediation: "Disable legacy TLS and require TLS 1.2 or newer.", Evidence: model.Evidence{URL: safeURL(response.Request.URL), Details: map[string]string{"version": tlsVersionName(state.Version)}},
		})
	}
	if len(state.PeerCertificates) == 0 {
		return
	}
	leaf := state.PeerCertificates[0]
	days := int(time.Until(leaf.NotAfter).Hours() / 24)
	if days < 30 {
		severity := model.SeverityMedium
		if days < 7 {
			severity = model.SeverityHigh
		}
		appendFinding(report, model.Finding{
			RuleID: "web.tls.certificate-expiring", Module: "tls", Title: "TLS certificate expires soon", Severity: severity, Confidence: "high",
			Description: "The leaf certificate is close to its expiration date.", Remediation: "Renew and deploy the certificate before it expires.", Evidence: model.Evidence{URL: safeURL(response.Request.URL), Details: map[string]string{"not_after": leaf.NotAfter.UTC().Format(time.RFC3339), "days_remaining": strconv.Itoa(days)}},
		})
	}
	if key, ok := leaf.PublicKey.(*rsa.PublicKey); ok && key.N.BitLen() < 2048 {
		appendFinding(report, model.Finding{
			RuleID: "web.tls.weak-rsa-key", Module: "tls", Title: "TLS certificate uses a weak RSA key", Severity: model.SeverityHigh, Confidence: "high", CWE: "CWE-326",
			Description: "The certificate RSA key is shorter than 2048 bits.", Remediation: "Replace the certificate with one using RSA 2048 bits or stronger, or a suitable modern elliptic curve.", Evidence: model.Evidence{URL: safeURL(response.Request.URL), Details: map[string]string{"rsa_bits": strconv.Itoa(key.N.BitLen())}},
		})
	}
	if weakSignature(leaf.SignatureAlgorithm) {
		appendFinding(report, model.Finding{
			RuleID: "web.tls.weak-signature", Module: "tls", Title: "Certificate uses a legacy signature algorithm", Severity: model.SeverityHigh, Confidence: "high", CWE: "CWE-327",
			Description: "The leaf certificate uses MD5 or SHA-1 for its signature.", Remediation: "Replace the certificate with one signed using SHA-256 or stronger.", Evidence: model.Evidence{URL: safeURL(response.Request.URL), Details: map[string]string{"algorithm": leaf.SignatureAlgorithm.String()}},
		})
	}
}

func weakSignature(algorithm x509.SignatureAlgorithm) bool {
	switch algorithm {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return true
	default:
		return false
	}
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("TLS 0x%04x", version)
	}
}

func truncate(value string, max int) string {
	value = strings.TrimSpace(value)
	runes := []rune(value)
	if len(runes) <= max {
		return value
	}
	return string(runes[:max]) + "..."
}

func safeURL(input *url.URL) string {
	if input == nil {
		return ""
	}
	clean := *input
	clean.User = nil
	clean.RawQuery = ""
	clean.ForceQuery = false
	clean.Fragment = ""
	return truncate(clean.String(), 2_048)
}

func sanitizeNetworkError(err error) error {
	var urlError *url.Error
	if !errors.As(err, &urlError) {
		if errors.Is(err, context.DeadlineExceeded) {
			return errors.New("network request timed out")
		}
		if errors.Is(err, context.Canceled) {
			return errors.New("network request was canceled")
		}
		return errors.New("network request failed")
	}
	parsed, parseErr := url.Parse(urlError.URL)
	display := "[invalid URL]"
	if parseErr == nil {
		display = safeURL(parsed)
	}
	reason := "network request failed"
	if urlError.Timeout() || errors.Is(urlError.Err, context.DeadlineExceeded) {
		reason = "network request timed out"
	} else if errors.Is(urlError.Err, context.Canceled) {
		reason = "network request was canceled"
	}
	operation := strings.ToLower(strings.TrimSpace(urlError.Op))
	if operation != "get" && operation != "head" {
		operation = "request"
	}
	return errors.New(truncate(fmt.Sprintf("%s %q: %s", operation, display, reason), 1_024))
}
