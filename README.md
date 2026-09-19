# roots

[![Go Reference](https://img.shields.io/badge/go-reference-blue?logo=go&logoColor=white&style=for-the-badge)](https://pkg.go.dev/github.com/kenjoe41/roots)
[![GitHub license](https://img.shields.io/badge/LICENSE-MIT-GREEN?style=for-the-badge)](LICENSE)

roots walks public [Certificate Transparency](https://certificate.transparency.dev/) logs and
streams every hostname it finds to stdout — pulled from a certificate's Subject `CommonName`,
every SAN `dNSName` and `uniformResourceIdentifier` entry, the domain half of SAN email
addresses, and (for constrained CA certs) the Name Constraints extension. Both final
certificates and precertificates are parsed; precertificates make up a large share of most
logs' entries (a CA logs one to obtain an embedded SCT, often without ever submitting a final
cert), so skipping them — which an earlier version of this tool did by accident — silently
drops a large fraction of the domains a log actually contains.

It's a firehose over CT logs, not a targeted lookup: point it at nothing and it fetches from
every log server in Google's broader
[all_logs_list.json](https://www.gstatic.com/ct/log_list/v3/all_logs_list.json) feed —
deliberately not the narrower `log_list.json`, which only lists logs Chrome currently trusts
for *new* certs. A log dropped from that trust list keeps serving the certificates it already
has indefinitely, and for domain discovery that historical data matters more than current
browser-trust status. On top of that, roots probes for even older shards of every dated log
family (`argonNNNNhN`, `nimbusNNNN`, etc.) that have aged out of *both* Google feeds but are
still live — see [How it works](#how-it-works). Together these run concurrently, forever (or
until each log's tree is fully walked).

Monitoring a single log is not sufficient on its own: browser CT policy requires each
certificate to carry SCTs from at least two independent log operators, and different CAs
submit to different subsets of the ecosystem's logs. No single log operator sees more than a
fraction of issued certificates — walking every operator's logs is the only way to approach
full coverage.

Pair it with `grep` to watch for domains matching a pattern, or feed it into other recon
tooling such as [goSubsWordlist](https://github.com/kenjoe41/goSubsWordlist).

## How it works

- Fetches `all_logs_list.json`, drops known non-production entries (Google's `testtube`
  conformance-testing log — 1.6B+ entries of synthetic test certs — and the literal
  `ct.example.com` placeholder entries), then probes for historical shards of every dated log
  family that aren't in the feed at all. Sharded logs (Google `argon`/`xenon`, Sectigo
  `mammoth`/`sabre`/`elephant`/`tiger`, DigiCert `wyvern`/`sphinx`, Let's Encrypt `oak`,
  Cloudflare `nimbus`, ...) roll over every half year or year, and Google's published feeds
  only retain roughly the last couple of years of shard names even though the servers keep
  serving indefinitely — `xenon2025h2` and `argon2025h2`, for example, are each billions of
  entries and live, but appear in neither feed. The prober walks backward from each family's
  oldest known shard and stops after a few consecutive misses, so it finds these without
  needing them listed anywhere. It can only rediscover shards within a family's current naming
  scheme, not a family's pre-rename predecessor (e.g. Google's older `daedalus`/`submariner`
  logs use unrelated names) — those are only reachable because `all_logs_list.json` records
  them explicitly.
- Spawns one goroutine per log server (published + discovered).
- Each log server is walked in `1000`-entry batches by `-workers` (default `20`) concurrent
  workers, with exponential backoff on transient fetch errors.
- All HTTP requests (log list, `GetSTH`, `GetRawEntries`) go through a shared
  [retryablehttp](https://github.com/hashicorp/go-retryablehttp) client that retries on `429`
  and `5xx` automatically, honoring a log server's `Retry-After` header on `429` instead of
  guessing a backoff — CT log servers rate-limit aggressively, and this is what lets a run
  survive that instead of silently dropping a whole log server on the first `429`. Retries are
  logged to stderr as `[http retry] ...` so you can see when a log is throttling you.
- **`-proxies` (default on)**: at startup, harvests free public proxies from ten real,
  regularly-updated feeds, validates each one with a real CONNECT-tunnel check, and — for every
  request roots makes from then on — round-robins across whatever validated as live. This is
  the actual fix for a real, live-hit problem: some log families (`argon2025h1/h2`,
  `xenon2025h1/h2`, `nimbus2025`, ...) are historical shards discovered via the shard-prober
  above, so they never get `roots-seed`'s "start from now" treatment and genuinely need a full
  multi-billion-entry walk from index 0 — and a single client IP hitting a log server that hard
  gets rate-limited into a crawl that barely moves for days. Spreading requests across many
  source IPs is a real, direct answer to that, not a cosmetic speedup. Each proxy's reliability
  is tracked with an EWMA health score; a proxy that starts failing is first excluded from
  selection (a transient blip can still recover it) and, only after a long enough run of
  consecutive failures with no success in between, pruned from the pool outright. When a request
  through a proxy fails, `retryablehttp` retries it — and because a fresh proxy is picked on
  every attempt, the retry goes out through a *different* proxy automatically. Because free
  proxies churn within hours, the pool also re-harvests every 30 minutes and merges in
  newly-live proxies (dead ones already pruned), so a multi-day crawl doesn't slowly starve down
  to whatever happened to be alive at startup. Harvesting nothing (no internet access to the
  proxy-list sources, every candidate dead) falls back to a direct connection automatically —
  this flag never blocks or breaks a run, it only ever helps when proxies are actually available.
  Proxy health is logged to stderr as `[proxypool] ...` every couple of minutes so you can watch
  the pool's size and quality over a long run.
- **`-max-conns` (default `60`)**: a global cap on how many connections roots holds open at once,
  across everything it does — the crawl, the proxy-harvest validation probes, and the shard prober
  combined. This matters: `-workers` × (number of logs) can otherwise be ~940 simultaneous
  connections, each (with `-proxies` on) dialing a different proxy, which is enough to exhaust a
  home router's NAT/conntrack table and freeze the **entire** network, not just roots (a real,
  hit-in-practice incident). The cap is enforced at the dial level — every TCP connection acquires
  a slot before it's opened and frees it only when closed — so idle keep-alives, in-progress dials
  to dead proxies, and harvest probes all count against the one budget. The default is deliberately
  conservative because the network is usually shared with other processes (a browser, a torrent
  client); raise it if roots has the network mostly to itself and you want more throughput.
- Every valid hostname found (validated against RFC 6125 syntax rules) is printed to stdout,
  one per line, as soon as it's parsed — no buffering or deduplication.
- Progress and errors are written to stderr, so stdout stays a clean, pipeable domain list:

  ```shell
  ./roots > domains.txt
  ```

- `-jsonl <path>` optionally appends one JSON record per certificate — `{"log", "index",
  "hostnames", "organization"}` — to the given file, for downstream correlation that a flat
  hostname stream can't support on its own. In particular: two hostnames that individually look
  unrelated but appear as SAN entries on the *same* certificate is a strong same-owner signal
  (companies commonly bundle several of their own brand domains into one multi-SAN cert).
  Default stdout behavior is unaffected either way.

  ```shell
  ./roots -jsonl certs.jsonl > domains.txt
  ```

## Package layout

roots is a CLI, not a library — everything under `internal/` is an implementation package the
Go toolchain refuses to let other modules import.

| Package               | Responsibility                                                     |
|-----------------------|---------------------------------------------------------------------|
| `internal/loglist`    | Fetching/parsing the CT log list; hostname syntax validation.       |
| `internal/shardprobe` | Discovering live historical shards not present in the published log list. |
| `internal/certscan`   | Parsing CT log entries (both entry types) into certificates, and extracting every hostname-bearing field from one. |
| `internal/cert`       | Per-log-server resume-state persistence under `~/certwatch/logs/`.  |
| `internal/proxypool`  | Free-proxy harvesting/validation + health-weighted round-robin selection, used when `-proxies` is on. Adapted from a sibling project's evasion-proxy package — see the package's own doc comment for exactly what carried over and what didn't. |

## Resume support

roots persists the last index processed for each log server under
`~/certwatch/logs/<log-server>.json`. On the next run, each log server resumes from its saved
index instead of starting over from zero — useful since some logs have hundreds of millions of
entries and a full walk can take a long time.

Delete `~/certwatch/logs/` to force a full re-walk from scratch.

## Install

```shell
go install -v github.com/kenjoe41/roots@latest
```

## Usage

```shell
roots > domains.txt

# tune concurrency and disable the proxy harvest explicitly if needed
roots -workers 40 > domains.txt
roots -proxies=false > domains.txt

# raise the global connection cap when roots has the network to itself,
# or lower it further on a busy/shared connection
roots -max-conns 150 > domains.txt
roots -max-conns 30  > domains.txt
```

roots always walks every log in the current CT log list; interrupt it with Ctrl-C at any
point — progress up to the last completed batch per log is saved. See `-h` for the full flag
list (`-workers`, `-proxies`, `-jsonl`).

## Caveats

- This is a high-volume crawl: CT logs are large, and roots deliberately does not rate-limit
  itself beyond the built-in backoff-on-error. Be considerate of the log operators you're
  hitting.
- No deduplication is performed. The same hostname will appear multiple times if it shows up
  in multiple certificates (SAN reissues, multiple logs, etc.) — dedupe downstream if needed,
  e.g. `./roots | sort -u`.
- Free public proxies (used when `-proxies` is on, the default) are untrusted middlemen by
  nature. roots does **not** disable TLS verification for proxied requests — the CONNECT tunnel
  still performs a real, verified TLS handshake end-to-end with the actual log server
  (`ct.googleapis.com`, etc.), so a proxy sees only opaque encrypted bytes and can't silently
  substitute forged CT data. Everything fetched is public CT log data anyway; no
  credentials/secrets ever cross that hop. If you'd still rather not route through third-party
  proxies at all, run with `-proxies=false`.

## License

MIT — see [LICENSE](LICENSE).
