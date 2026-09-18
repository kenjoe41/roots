// Package proxypool distributes roots' own outbound HTTP requests across a
// pool of free public proxies, so a multi-billion-entry historical CT-log
// crawl isn't bottlenecked by one client IP's rate limit on the log server.
//
// Adapted from shadowweave's internal/evasion/stealthcloak/proxy package
// (harvester.go/health.go/rotator.go) — that package's core logic (fetching
// and validating free proxy lists, EWMA health scoring) is real, proven
// code worth reusing, but shadowweave's version was shaped by a different
// world: a long-lived engine sharing one persistent, BadgerDB-backed proxy
// pool across many concurrent evasion-sensitive attack modules, re-harvesting
// on a 6-hour ticker, with per-domain sticky sessions and anonymity-level
// classification to avoid tipping off a WAF. roots is a one-shot CLI crawl
// with no adversary to hide from — it harvests once at startup, round-robins
// across whatever it found for the run's duration, and never persists a
// proxy list between runs (free proxies churn within hours, so a fresh
// harvest is more correct than a stale cached one anyway). Anonymity
// detection, domain stickiness, and vault persistence are cut entirely as
// dead weight for this use case, not stubbed out.
package proxypool

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// defaultSources are real, publicly maintained free-proxy-list feeds —
// carried over verbatim from shadowweave's own harvester, which already
// proved these out as live, regularly updated sources.
var defaultSources = []string{
	"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
	"https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
	"https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/https/data.txt",
	"https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt",
	"https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/https.txt",
	"https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/http.txt",
	"https://raw.githubusercontent.com/dpangestuw/Free-Proxy/main/http_proxies.txt",
	"https://raw.githubusercontent.com/zloi-user/hideip.me/master/https.txt",
	"https://raw.githubusercontent.com/elliottophellia/proxylist/master/results/http/global/http_checked.txt",
	"https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt",
}

// defaultValidatorURL is what a candidate proxy must successfully CONNECT-
// tunnel to in order to be considered live. Google's own connectivity-check
// endpoint: lightweight (204, no body), globally reachable, and — since
// several of the very logs this pool exists to help crawl are themselves
// googleapis.com-hosted — a proxy that can reach this can very likely reach
// them too.
const defaultValidatorURL = "https://www.gstatic.com/generate_204"

const (
	validateTimeout     = 12 * time.Second
	fetchSourceTimeout  = 10 * time.Second
	validateConcurrency = 100
)

// validIPPortRegex matches bare "ip:port" strings from proxy lists —
// intentionally permissive, since actual liveness is checked separately.
var validIPPortRegex = regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+`)

// harvest fetches every source concurrently, validates every distinct
// candidate concurrently, and returns the live ones normalised to
// "http://ip:port". A source that fails to fetch is skipped with a warning
// printed to stderr — matching this codebase's existing "warn and keep
// going" convention (see main.go's own per-log error handling) rather than
// aborting the whole harvest over one dead source.
func harvest(ctx context.Context, sources []string, validatorURL string) []string {
	fetchClient := &http.Client{Timeout: fetchSourceTimeout}

	candidates := make(map[string]struct{})
	for _, src := range sources {
		list, err := fetchList(ctx, fetchClient, src)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[proxypool] failed to fetch %s: %v\n", src, err)
			continue
		}
		for _, p := range list {
			candidates[p] = struct{}{}
		}
	}

	type result struct {
		addr string
		ok   bool
	}
	jobs := make(chan string)
	results := make(chan result)
	var wg sync.WaitGroup
	for i := 0; i < validateConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for addr := range jobs {
				results <- result{addr: addr, ok: validate(ctx, addr, validatorURL)}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for addr := range candidates {
			select {
			case jobs <- addr:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		wg.Wait()
		close(results)
	}()

	var live []string
	for r := range results {
		if r.ok {
			live = append(live, normaliseAddr(r.addr))
		}
	}
	return live
}

// fetchList retrieves a proxy list from src, supporting both line-per-proxy
// (ip:port) and JSON-array formats.
func fetchList(ctx context.Context, client *http.Client, src string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status: %d", resp.StatusCode)
	}

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading body: %w", err)
	}

	trimmed := bytes.TrimLeft(rawBody, " \t\r\n")
	if len(trimmed) == 0 {
		return nil, nil
	}

	if trimmed[0] == '[' || trimmed[0] == '{' {
		return parseJSONList(rawBody), nil
	}

	var proxies []string
	scanner := bufio.NewScanner(bytes.NewReader(rawBody))
	for scanner.Scan() {
		if match := validIPPortRegex.FindString(scanner.Text()); match != "" {
			proxies = append(proxies, match)
		}
	}
	return proxies, scanner.Err()
}

// parseJSONList extracts proxy addresses from the handful of JSON shapes
// real free-proxy-list feeds actually use: a bare string array, an object
// array with ip/port fields, or either of those wrapped in a "data" key.
// An unrecognised or malformed shape returns nil, not an error — one
// oddly-formatted source shouldn't fail the whole harvest.
func parseJSONList(body []byte) []string {
	var strArr []string
	if err := json.Unmarshal(body, &strArr); err == nil && len(strArr) > 0 {
		return strArr
	}

	type proxyEntry struct {
		IP   string `json:"ip"`
		Port any    `json:"port"`
	}
	toAddrs := func(entries []proxyEntry) []string {
		addrs := make([]string, 0, len(entries))
		for _, e := range entries {
			if e.IP == "" {
				continue
			}
			portStr := fmt.Sprintf("%v", e.Port)
			if portStr == "" || portStr == "<nil>" {
				continue
			}
			addrs = append(addrs, net.JoinHostPort(e.IP, portStr))
		}
		return addrs
	}

	var entries []proxyEntry
	if err := json.Unmarshal(body, &entries); err == nil && len(entries) > 0 {
		return toAddrs(entries)
	}

	var wrapped struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &wrapped); err == nil && len(wrapped.Data) > 0 {
		if err := json.Unmarshal(wrapped.Data, &strArr); err == nil && len(strArr) > 0 {
			return strArr
		}
		if err := json.Unmarshal(wrapped.Data, &entries); err == nil && len(entries) > 0 {
			return toAddrs(entries)
		}
	}

	return nil
}

// validate reports whether proxyAddr can successfully CONNECT-tunnel a
// request to validatorURL. Only transport-level success matters — any
// response at all (2xx-3xx or otherwise) means the proxy itself works; a
// non-2xx/3xx status still means the tunnel succeeded, so unlike
// shadowweave's version (which required 2xx/3xx to also confirm the
// validator endpoint approved of the request) this only cares that the
// PROXY functioned, since the real traffic afterwards goes to CT log
// servers with their own, different status-code semantics (429 included).
func validate(ctx context.Context, proxyAddr, validatorURL string) bool {
	timeoutCtx, cancel := context.WithTimeout(ctx, validateTimeout)
	defer cancel()

	proxyURL, err := url.Parse(ensureScheme(proxyAddr))
	if err != nil {
		return false
	}

	transport := &http.Transport{
		Proxy:               http.ProxyURL(proxyURL),
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSHandshakeTimeout: 5 * time.Second,
		DisableKeepAlives:   true,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // validating proxy reachability only, no sensitive data crosses this connection
	}
	client := &http.Client{Transport: transport, Timeout: validateTimeout}

	req, err := http.NewRequestWithContext(timeoutCtx, http.MethodHead, validatorURL, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return true
}

func normaliseAddr(addr string) string {
	if strings.HasPrefix(addr, "http://") || strings.HasPrefix(addr, "https://") {
		return addr
	}
	return "http://" + addr
}

func ensureScheme(addr string) string {
	if strings.HasPrefix(addr, "http://") || strings.HasPrefix(addr, "https://") {
		return addr
	}
	return "http://" + addr
}
