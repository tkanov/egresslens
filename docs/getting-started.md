# Getting started: example flow (Sample app + UI)

This walkthrough follows the full flow: start backend, start frontend, run the CLI, upload the JSONL, and view results in the UI.

## Prerequisites

- Docker 20.10+
- Python 3.9+ for the CLI, 3.10+ for the backend
- Node.js 20.19+ (or 22.13+)

## Step 1: Start the backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Leave this terminal running. The API will be available at `http://localhost:8000`.

## Step 2: Start the frontend

```bash
cd frontend
npm install
npm run dev
```

Open the UI at `http://localhost:5173`.

## Step 3: Install the CLI

In a third terminal, from the repo root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e cli/
```

`pip install -e cli/` is what creates the `egresslens` command. Installing
`cli/requirements.txt` on its own gets you the dependencies but no command.

## Step 4: Build the tracing image

From the repo root:

```bash
docker build -t egresslens/base:latest .
```

The CLI defaults to this local image.

## Step 5: Run a CLI capture

From the repo root:

```bash
egresslens run-app ./sample_app --args "dns example.com"
```

Example:

```
 $ egresslens run-app ./sample_app --args "all python.org"

✓ Run complete (exit code: 0)
  Run ID: 2e79c74f-d012-4028-b5a6-0ae3630df627
  Output: /workspaces/egresslens/egresslens-output
  Events: 14 network events captured
  Unique destinations: 6 IPs, 6 IP:port pairs
  Dependencies: Installed from requirements.txt

```


Note: here we're using the sample app included in this repo.


## Step 6: Review the generated files

![egresslens-output](images/files-outputs.png)


The run creates `egresslens-output/` with:

- `egress.jsonl` - network events

Sample:

```json
{"ts": 1770477764.27391, "pid": 12, "event": "connect", "family": "inet", "proto": "tcp", "dst_ip": "192.168.1.1", "dst_port": 53, "result": "ok", "errno": null}
{"ts": 1770477764.279734, "pid": 12, "event": "connect", "family": "inet", "proto": "tcp", "dst_ip": "151.101.128.223", "dst_port": 443, "result": "ok", "errno": null}
{"ts": 1770477764.280498, "pid": 12, "event": "connect", "family": "inet", "proto": "tcp", "dst_ip": "151.101.192.223", "dst_port": 443, "result": "ok", "errno": null}
{"ts": 1770477764.28121, "pid": 12, "event": "connect", "family": "inet", "proto": "tcp", "dst_ip": "151.101.0.223", "dst_port": 443, "result": "ok", "errno": null}
```

`event` records which syscall named the destination: `connect`, or `sendto` /
`sendmsg` / `sendmmsg` for a datagram sent on an unconnected socket. See
[Which syscalls are parsed](#which-syscalls-are-parsed).


- `egress.strace` - captured `strace` outputs

Sample:

```log
12    1770477764.115770 connect(3, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("192.168.1.1")}, 16) = 0
12    1770477764.116208 sendmmsg(3, [{msg_hdr={msg_name=NULL, msg_namelen=0, msg_iov=[{iov_base="N\247\1\0\0\1\0\0\0\0\0\0\4pypi\3org\0\0\1\0\1", iov_len=26}], msg_iovlen=1, msg_controllen=0, msg_flags=0}, msg_len=26}, {msg_hdr={msg_name=NULL, msg_namelen=0, msg_iov=[{iov_base="k\246\1\0\0\1\0\0\0\0\0\0\4pypi\3org\0\0\34\0\1", iov_len=26}], msg_iovlen=1, msg_controllen=0, msg_flags=0}, msg_len=26}], 2, MSG_NOSIGNAL) = 2
12    1770477764.116825 recvfrom(3, "k\246\201\200\0\1\0\0\0\0\0\0\4pypi\3org\0\0\34\0\1", 2048, 0, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("192.168.1.1")}, [28 => 16]) = 26
12    1770477764.117768 recvfrom(3, "N\247\201\200\0\1\0\4\0\0\0\0\4pypi\3org\0\0\1\0\1\4pypi\3org\0\0\1\0\1\0\0\0\0\0\4\227e\0\337\4pypi\3org\0\0\1\0\1\0\0\0\0\0\4\227e\300\337\4pypi\3org\0\0\1\0\1\0\0\0\0\0\4\227e@\337\4pypi\3org\0\0\1\0\1\0\0\0\0\0\4\227e\200\337", 65536, 0, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("192.168.1.1")}, [28 => 16]) = 122
12    1770477764.118570 socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_ROUTE) = 3
12    1770477764.118818 bind(3, {sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, 12) = 0
12    1770477764.120403 getsockname(3, {sa_family=AF_NETLINK, nl_pid=12, nl_groups=00000000}, [12]) = 0
```


- `run.json` - run metadata
- `cmd_stdout` - app stdout
- `cmd_stderr` - app stderr


#### Preview a few events:

```bash
$ head -n 5 egresslens-output/egress.jsonl
{"ts": 1770477764.11577, "pid": 12, "event": "connect", "family": "inet", "proto": "tcp", "dst_ip": "192.168.5.1", "dst_port": 53, "result": "ok", "errno": null}
{"ts": 1770477764.122074, "pid": 12, "event": "connect", "family": "inet", "proto": "tcp", "dst_ip": "151.101.0.223", "dst_port": 443, "result": "ok", "errno": null}
{"ts": 1770477764.122886, "pid": 12, "event": "connect", "family": "inet", "proto": "tcp", "dst_ip": "151.101.192.223", "dst_port": 443, "result": "ok", "errno": null}
```


## Step 7: Upload the JSONL in the UI

Use the upload page to submit `egresslens-output/egress.jsonl`. That file is the
only required one; the other three pickers each add something:

- `egresslens-output/run.json` in the run metadata picker — command, image, exit code, timing
- `egresslens-output/egress.strace` in the passive DNS trace picker — domains for public IPs
- a `policy.json` allowlist in the egress allowlist picker — a pass/fail verdict (see Step 9)

For domains, the backend first uses passive UDP DNS A-record answers visible in `egress.strace`, then falls back to bounded reverse DNS for unresolved public IPv4 addresses. JSONL-only uploads remain valid; unresolved destinations simply show an empty domain value.


![Upload screen](images/ui-frontend.png)

## Step 8: View the results in the UI

After upload, the report page shows the KPIs, timeline, and top destinations. Enriched reports show a primary domain for each destination when available, with a source hint such as `passive_dns` or `reverse_dns`. Markdown export includes the domain source and enrichment counters.

![Report view](images/report.png)

## Step 9: Add an allowlist for a verdict

To turn the report into a pass/fail check, write the destinations the app is
supposed to reach into a `policy.json`:

```json
{
  "allow": [
    "example.com",
    "*.python.org",
    "192.168.1.1/32"
  ]
}
```

Upload it in the egress allowlist picker alongside the same `egress.jsonl`. Every
observed destination is then checked against the list, and the report gains a
verdict:

- **PASS** — everything observed was on the list
- **FAIL** — something was not, raising a high-severity "Unexpected destinations" flag
- **INCONCLUSIVE** — no destinations were observed at all, so the list was never exercised

INCONCLUSIVE is not a quiet pass: it means the capture gave the allowlist nothing
to judge, which looks the same whether the run was genuinely silent or the
capture failed.

Rule syntax, and why `domain` rules are advisory while `ip`/CIDR rules are a hard
gate, are covered in [docs/policy.md](policy.md).

Two things to watch when writing a policy: `allow` is the only key honoured — a
`deny` block is silently ignored rather than rejected, so it will not do what it
looks like it does — and a rule combining `domain` and `ip` is not an IP hard
gate; write the `ip` rule separately.

---

## Limitations

### Domain enrichment scope

Domain enrichment is backend-only. The CLI still writes the same `egress.jsonl` event format, and enrichment is applied only when a report is uploaded. Passive DNS currently parses UDP DNS A-record responses read via `recvfrom` or `recvmsg` in `egress.strace`; DNS-over-HTTPS, DNS-over-TLS, cached DNS, TCP DNS, AAAA records, IPv6 enrichment, and answers received via `recvmmsg` are outside the current scope.

Reverse DNS fallback is enabled by default but bounded by configuration: `ENRICHMENT_REVERSE_DNS_TIMEOUT_SECONDS` defaults to `0.5`, and `ENRICHMENT_REVERSE_DNS_MAX_IPS` defaults to `100`. It skips private, loopback, link-local, multicast, unspecified, and reserved ranges.

### IPv4 only

The current MVP captures **IPv4 (AF_INET) destinations only**.

- All events in `egress.jsonl` have `"family": "inet"` (IPv4)
- IPv6 destinations do not appear in the event logs
- The `strace` parser in the CLI only recognizes the AF_INET socket family
- IPv6 destinations reached via `connect()` are counted and reported as `counts.ipv6_connects_skipped` in `run.json`, so a report does not silently understate egress. An IPv6 destination named on a `sendto`/`sendmsg`/`sendmmsg` call is currently neither captured nor counted.

### Which syscalls are parsed

A destination is captured from either `connect()` or, when the socket is unconnected, from the `sendto`/`sendmsg`/`sendmmsg` call that names it. Both matter: `dnspython` resolves with `sendto()` on an unconnected socket and never calls `connect()`, as do statsd clients, syslog-over-UDP, NTP, and Python QUIC stacks. A send on a socket that was already `connect()`ed prints `msg_name=NULL` and is not re-reported, so there is no double counting.

Only syscalls in strace's `network` class are traced (`-e trace=network`). Egress submitted by another mechanism — `io_uring`, for example — is not captured at all and cannot raise a policy FAIL.

**Why**: IPv6 support requires:
- Additional strace event parsing (AF_INET6 patterns)
- Updated frontend/backend to display IPv6-specific formats (e.g., IPv6 address notation)
- Testing across IPv6-only and dual-stack networks

This limitation will be addressed in future versions. For now, EgressLens is suitable for monitoring IPv4-only applications and dual-stack apps that primarily use IPv4 for egress.
