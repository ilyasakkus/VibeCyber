package control

import (
	"net/url"
	"strings"

	"github.com/webcyber/webcyber/internal/model"
	"github.com/webcyber/webcyber/internal/scan"
)

const invalidWebTarget = "[invalid web URL]"

// publicTarget returns the target representation that may cross the control
// API boundary. The original value remains only in the private scan.Config.
func publicTarget(config scan.Config) string {
	if config.Type != model.ScanTypeWeb {
		return config.Target
	}
	return redactWebTarget(config.Target)
}

func redactWebTarget(raw string) string {
	candidate, err := url.Parse(raw)
	if err != nil ||
		candidate.Opaque != "" ||
		(!strings.EqualFold(candidate.Scheme, "http") && !strings.EqualFold(candidate.Scheme, "https")) ||
		candidate.Hostname() == "" {
		return invalidWebTarget
	}
	candidate.Scheme = strings.ToLower(candidate.Scheme)
	candidate.User = nil
	candidate.RawQuery = ""
	candidate.ForceQuery = false
	candidate.Fragment = ""
	candidate.RawFragment = ""

	// url.Parse accepts some whitespace around otherwise relative inputs. The
	// absolute checks above reject those, and this final check keeps control
	// characters out of API-visible metadata.
	safe := candidate.String()
	if strings.ContainsAny(safe, "\x00\r\n") {
		return invalidWebTarget
	}
	return safe
}
