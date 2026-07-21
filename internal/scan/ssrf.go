package scan

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

type resolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

type ssrfGuard struct {
	resolver resolver
	dialer   net.Dialer
	mu       sync.RWMutex
	pinned   map[string][]net.IPAddr
}

func newSSRFGuard(timeout time.Duration) *ssrfGuard {
	return &ssrfGuard{
		resolver: net.DefaultResolver,
		dialer:   net.Dialer{Timeout: timeout, KeepAlive: 15 * time.Second},
		pinned:   make(map[string][]net.IPAddr),
	}
}

func (g *ssrfGuard) validateURL(ctx context.Context, candidate *url.URL) error {
	if candidate == nil {
		return fmt.Errorf("URL is missing")
	}
	scheme := strings.ToLower(candidate.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("URL scheme must be http or https")
	}
	if candidate.User != nil {
		return fmt.Errorf("URL user information is not allowed")
	}
	host := strings.TrimSuffix(strings.ToLower(candidate.Hostname()), ".")
	if host == "" {
		return fmt.Errorf("URL host is missing")
	}
	if strings.ContainsAny(host, "\x00\r\n") {
		return fmt.Errorf("URL host contains invalid characters")
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return fmt.Errorf("local hostnames are not allowed")
	}
	if port := candidate.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return fmt.Errorf("URL port is invalid")
		}
	}
	_, err := g.resolveAndPin(ctx, host)
	return err
}

func (g *ssrfGuard) resolveAndPin(ctx context.Context, host string) ([]net.IPAddr, error) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	g.mu.RLock()
	known := cloneIPAddrs(g.pinned[host])
	g.mu.RUnlock()
	if len(known) > 0 {
		return known, nil
	}

	if parsed := net.ParseIP(host); parsed != nil {
		addresses := []net.IPAddr{{IP: parsed}}
		if err := validatePublicAddresses(addresses); err != nil {
			return nil, err
		}
		g.pin(host, addresses)
		return addresses, nil
	}

	addresses, err := g.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve host %q: %w", host, err)
	}
	if err := validatePublicAddresses(addresses); err != nil {
		return nil, fmt.Errorf("host %q: %w", host, err)
	}
	g.pin(host, addresses)
	return cloneIPAddrs(addresses), nil
}

func (g *ssrfGuard) pin(host string, addresses []net.IPAddr) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.pinned[host]) == 0 {
		g.pinned[host] = cloneIPAddrs(addresses)
	}
}

func (g *ssrfGuard) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid dial address: %w", err)
	}
	addresses, err := g.resolveAndPin(ctx, host)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, candidate := range addresses {
		conn, dialErr := g.dialer.DialContext(ctx, network, net.JoinHostPort(candidate.IP.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
	}
	return nil, fmt.Errorf("connect to approved public address: %w", lastErr)
}

func cloneIPAddrs(in []net.IPAddr) []net.IPAddr {
	out := make([]net.IPAddr, len(in))
	copy(out, in)
	return out
}

func validatePublicAddresses(addresses []net.IPAddr) error {
	if len(addresses) == 0 {
		return fmt.Errorf("host has no IP addresses")
	}
	for _, address := range addresses {
		parsed, ok := netip.AddrFromSlice(address.IP)
		if !ok {
			return fmt.Errorf("host returned an invalid IP address")
		}
		parsed = parsed.Unmap()
		if isForbiddenAddress(parsed) {
			return fmt.Errorf("non-public, local, or reserved IP address is not allowed")
		}
	}
	return nil
}

var forbiddenPrefixes = mustPrefixes(
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.88.99.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"::/128",
	"::1/128",
	"64:ff9b::/96",
	"64:ff9b:1::/48",
	"100::/64",
	"2001::/23",
	"2001:db8::/32",
	"2002::/16",
	"fc00::/7",
	"fe80::/10",
	"ff00::/8",
)

func mustPrefixes(values ...string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefixes = append(prefixes, netip.MustParsePrefix(value))
	}
	return prefixes
}

func isForbiddenAddress(address netip.Addr) bool {
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsLoopback() || address.IsPrivate() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() || address.IsUnspecified() {
		return true
	}
	for _, prefix := range forbiddenPrefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}
