package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/trillian/client/backoff"
	"github.com/hashicorp/go-retryablehttp"

	"github.com/kenjoe41/roots/internal/cert"
	"github.com/kenjoe41/roots/internal/certscan"
	"github.com/kenjoe41/roots/internal/loglist"
	"github.com/kenjoe41/roots/internal/proxypool"
	"github.com/kenjoe41/roots/internal/shardprobe"
)

const (
	// all_logs_list.json (not log_list.json) is deliberate: log_list.json
	// only contains logs Chrome currently trusts for new certs, but a log
	// dropped from Chrome's trust list keeps serving its historical entries
	// indefinitely. all_logs_list.json additionally covers retired/rejected
	// logs - for domain discovery, historical data matters more than
	// current browser-trust status.
	logListURL = "https://www.gstatic.com/ct/log_list/v3/all_logs_list.json"

	batchSize  = 1000
	startIndex = int64(0)

	httpRetryMax     = 8
	httpRetryWaitMin = 1 * time.Second
	httpRetryWaitMax = 60 * time.Second

	probeClientTimeout = 5 * time.Second

	// proxyHarvestTimeout bounds how long startup waits for the proxy
	// harvest before giving up and crawling direct — a slow/unreachable
	// proxy-list source must never indefinitely delay the actual crawl.
	proxyHarvestTimeout = 60 * time.Second
)

// junkLogSubstrings marks known non-production or placeholder log entries
// that appear in Google's log list but aren't worth crawling: testtube is
// Google's public conformance-testing log (1.6B+ entries of synthetic test
// certs, essentially zero real domains for the crawl time it costs), and
// ct.example.com is a literal placeholder/schema-example entry.
var junkLogSubstrings = []string{
	"ct.googleapis.com/testtube",
	"ct.example.com",
}

func isJunkLog(logURL string) bool {
	for _, substr := range junkLogSubstrings {
		if strings.Contains(logURL, substr) {
			return true
		}
	}
	return false
}

// newHTTPClient returns an *http.Client shared by every request roots makes
// (log list fetch, GetSTH, GetRawEntries). CT log servers rate-limit
// aggressively under load; this transparently retries on 429/5xx and
// connection errors, honoring a server's Retry-After header on 429 instead
// of hammering it on a fixed interval. If rt is non-nil (the -proxies
// harvest produced a live pool), every request is additionally distributed
// across the proxy pool at the transport level - retryablehttp's own retry
// loop and this rotation compose cleanly, since a retried request just goes
// out through RoundTrip again and gets its own independent proxy pick.
func newHTTPClient(rt http.RoundTripper) *http.Client {
	rc := retryablehttp.NewClient()
	rc.RetryMax = httpRetryMax
	rc.RetryWaitMin = httpRetryWaitMin
	rc.RetryWaitMax = httpRetryWaitMax
	rc.Logger = retryLogger{}
	if rt != nil {
		rc.HTTPClient.Transport = rt
	}
	return rc.StandardClient()
}

// retryLogger adapts retryablehttp's leveled logging to this CLI's plain
// stderr progress style, so rate-limit backoffs are visible instead of
// silently absorbed.
type retryLogger struct{}

func (retryLogger) Error(msg string, kv ...interface{}) { logRetry("error", msg, kv) }
func (retryLogger) Warn(msg string, kv ...interface{})  { logRetry("warn", msg, kv) }
func (retryLogger) Info(msg string, kv ...interface{})  {}

// Debug fires on both "performing request" (every attempt, including the
// first) and "retrying request" (only when a retry was decided) - only the
// latter is worth surfacing, or every request would log a line.
func (retryLogger) Debug(msg string, kv ...interface{}) {
	if msg == "retrying request" {
		logRetry("retry", msg, kv)
	}
}

func logRetry(level, msg string, kv []interface{}) {
	fmt.Fprintf(os.Stderr, "[http %s] %s %v\n", level, msg, kv)
}

func main() {
	jsonlPath := flag.String("jsonl", "", "optional path to append one JSON record per certificate "+
		"(log, index, hostnames, organization) to, for downstream correlation (e.g. SAN co-occurrence "+
		"analysis). Off by default; stdout's plain hostname-per-line output is unaffected either way.")
	workersPerLog := flag.Int("workers", 20, "concurrent range-fetch workers per log server. Higher "+
		"values only help once -proxies gives those workers distinct source IPs to spread across - "+
		"more workers sharing one IP just means more of them backing off together under the same "+
		"rate limit.")
	useProxies := flag.Bool("proxies", true, "harvest free public proxies at startup and round-robin "+
		"every request across whatever validates as live, so a multi-billion-entry historical log "+
		"catch-up isn't bottlenecked by one client IP's rate limit. Falls back to a direct connection "+
		"automatically if no proxies validate (no internet access to the proxy-list sources, all dead, "+
		"etc) - never blocks the crawl on this.")
	flag.Parse()

	var pool *proxypool.Pool
	var proxyHarvestDone chan struct{}
	if *useProxies {
		pool = proxypool.New()
		proxyHarvestDone = make(chan struct{})
		go func() {
			defer close(proxyHarvestDone)
			ctx, cancel := context.WithTimeout(context.Background(), proxyHarvestTimeout)
			defer cancel()
			fmt.Fprintln(os.Stderr, "Harvesting free proxies...")
			n := pool.Harvest(ctx, nil, "")
			fmt.Fprintf(os.Stderr, "Harvested %d live proxies\n", n)
		}()
	}

	var jsonlChan chan certscan.Record
	var jsonlWG sync.WaitGroup
	if *jsonlPath != "" {
		f, err := os.OpenFile(*jsonlPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening -jsonl file: %s\n", err)
			os.Exit(1)
		}
		defer f.Close()

		jsonlChan = make(chan certscan.Record, batchSize)
		jsonlWG.Add(1)
		go func() {
			defer jsonlWG.Done()
			w := bufio.NewWriter(f)
			defer w.Flush()
			enc := json.NewEncoder(w)
			for rec := range jsonlChan {
				if err := enc.Encode(rec); err != nil {
					fmt.Fprintf(os.Stderr, "Error writing -jsonl record: %s\n", err)
				}
			}
		}()
	}

	fmt.Fprintln(os.Stderr, "Getting CT Logs list...")

	var transport http.RoundTripper
	if pool != nil {
		transport = proxypool.NewRotatingTransport(pool)
	}
	httpClient := newHTTPClient(transport)

	serverLogList, err := loglist.Fetch(logListURL, httpClient)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching CT log list: %s\n", err)
		os.Exit(1)
	}

	var logURLs []string
	for _, operator := range serverLogList.Operators {
		for _, serverLog := range operator.Logs {
			if !isJunkLog(serverLog.URL) {
				logURLs = append(logURLs, serverLog.URL)
			}
		}
	}

	fmt.Fprintln(os.Stderr, "Probing for historical log shards not in the published list...")
	probeClient := &http.Client{Timeout: probeClientTimeout}
	extraShards := shardprobe.Discover(context.Background(), probeClient, logURLs)
	if len(extraShards) > 0 {
		fmt.Fprintf(os.Stderr, "Found %d additional live historical shard(s):\n", len(extraShards))
		for _, url := range extraShards {
			fmt.Fprintf(os.Stderr, "  %s\n", url)
		}
		logURLs = append(logURLs, extraShards...)
	}

	// Check or create logs folder used to persist per-server resume state.
	if err := cert.CheckLogsFolder(); err != nil {
		fmt.Fprintf(os.Stderr, "Error preparing logs folder: %s\n", err)
		os.Exit(1)
	}

	domainsChan := make(chan string, batchSize*2)

	var domainsCount uint64
	var outputWG sync.WaitGroup
	outputWG.Add(1)
	go func() {
		defer outputWG.Done()
		for domain := range domainsChan {
			fmt.Println(domain)
			domainsCount++
		}
	}()

	if proxyHarvestDone != nil {
		<-proxyHarvestDone // bounded by proxyHarvestTimeout above - never blocks the crawl indefinitely
		pool.PrintStats()
	}

	var logsWG sync.WaitGroup
	for _, logURL := range logURLs {
		logsWG.Add(1)
		go func(logserverURL string) {
			defer logsWG.Done()
			if err := processLog(logserverURL, domainsChan, jsonlChan, httpClient, *workersPerLog); err != nil {
				fmt.Fprintf(os.Stderr, "[%s] processing failed: %s\n", logserverURL, err)
			}
		}(logURL)
	}

	logsWG.Wait()
	close(domainsChan)
	outputWG.Wait()
	if jsonlChan != nil {
		close(jsonlChan)
		jsonlWG.Wait()
	}

	fmt.Fprintf(os.Stderr, "Done walking the CT Logs Tree. Found %d domains.\n", domainsCount)
}

func processLog(logserverURL string, domainsChan chan<- string, jsonlChan chan<- certscan.Record, httpClient *http.Client, workersPerLog int) error {
	ctClient, err := client.New(logserverURL, httpClient, jsonclient.Options{})
	if err != nil {
		return fmt.Errorf("unable to construct CT log client: %w", err)
	}
	ctx := context.Background()

	ranges := genRanges(ctx, logserverURL, ctClient)
	if ranges == nil {
		return fmt.Errorf("unable to determine tree size")
	}

	var wg sync.WaitGroup
	for w := 0; w < workersPerLog; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runWorker(ctx, logserverURL, ranges, domainsChan, jsonlChan, ctClient)
		}()
	}
	wg.Wait()

	return nil
}

func runWorker(ctx context.Context, logserverURL string, ranges <-chan loglist.FetchRange, domainsChan chan<- string, jsonlChan chan<- certscan.Record, ctClient *client.LogClient) {
	if ctx.Err() != nil { // Prevent spinning when context is canceled.
		return
	}

	for r := range ranges {
		for r.Start <= r.End {
			if ctx.Err() != nil { // Prevent spinning when context is canceled.
				return
			}

			fmt.Fprintf(os.Stderr, "[%s] Fetching entry %d - %d...\n", logserverURL, r.Start, r.End)

			bo := &backoff.Backoff{
				Min:    1 * time.Second,
				Max:    30 * time.Second,
				Factor: 2,
				Jitter: true,
			}

			var resp *ct.GetEntriesResponse
			if err := bo.Retry(ctx, func() error {
				var err error
				resp, err = ctClient.GetRawEntries(ctx, r.Start, r.End)
				return err
			}); err != nil {
				// No error reporting for this worker yet, just retry.
				continue
			}

			for i, entry := range resp.Entries {
				index := r.Start + int64(i)
				rawEntry, err := ct.RawLogEntryFromLeaf(index, &entry)
				if _, ok := err.(x509.NonFatalErrors); !ok && err != nil {
					fmt.Fprintf(os.Stderr, "Erroneous certificate: log=%s index=%d err=%v\n",
						logserverURL, index, err)
					continue
				}
				leafCert, err := certscan.Leaf(rawEntry)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Unparseable certificate: log=%s index=%d err=%v\n",
						logserverURL, index, err)
					continue
				}
				for _, host := range certscan.Hostnames(leafCert) {
					domainsChan <- host
				}
				if jsonlChan != nil {
					jsonlChan <- certscan.NewRecord(logserverURL, index, leafCert)
				}
			}
			r.Start += int64(len(resp.Entries))

			if err := cert.WriteLogState(cert.LogState{LogServer: logserverURL, LogEndIndex: uint64(r.Start)}); err != nil {
				fmt.Fprintf(os.Stderr, "[%s] Failed to persist resume state: %s\n", logserverURL, err)
			}
		}
	}
	fmt.Fprintf(os.Stderr, "[%s] Done fetching entries...\n", logserverURL)
}

func genRanges(ctx context.Context, logserverURL string, ctClient *client.LogClient) <-chan loglist.FetchRange {
	batch := int64(batchSize)
	ranges := make(chan loglist.FetchRange)

	var logSTH *ct.SignedTreeHead
	bo := &backoff.Backoff{Min: 1 * time.Second, Max: 30 * time.Second, Factor: 2, Jitter: true}
	if err := bo.Retry(ctx, func() error {
		var err error
		logSTH, err = ctClient.GetSTH(ctx)
		return err
	}); err != nil {
		fmt.Fprintf(os.Stderr, "[%s] Failed to get STH: %s\n", logserverURL, err)
		return nil
	}
	endIndex := loglist.Max(startIndex, int64(logSTH.TreeSize))

	// Resume from the last persisted index for this log server, if any.
	start := startIndex
	if state, err := cert.ReadLogState(cert.LogState{LogServer: logserverURL}); err == nil && state.LogEndIndex > 0 {
		start = loglist.Min(int64(state.LogEndIndex), endIndex)
	}

	go func() {
		defer close(ranges)
		for start < endIndex {
			batchEnd := start + loglist.Min(endIndex-start, batch)
			next := loglist.FetchRange{Start: start, End: batchEnd - 1}
			select {
			case <-ctx.Done():
				return
			case ranges <- next:
			}
			start = batchEnd
		}
	}()

	return ranges
}
