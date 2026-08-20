# Egress policy reference

An egress policy is an allowlist of the destinations an app is expected to reach.
Upload one alongside a report and every observed destination is checked against
it, anything that does not match is reported as unexpected. This page is the full
reference. The [main README](../README.md#egress-policy) has the short version.

## Verdicts

The verdict is three-way, not a boolean:

| Verdict | Meaning | Flag raised |
|---|---|---|
| **PASS** | Every observed destination matched a rule | (none) |
| **FAIL** | At least one did not | "Unexpected destinations", high |
| **INCONCLUSIVE** | An allowlist was uploaded but nothing was observed | "Egress policy not evaluated", medium |

All three appear in the markdown export.

That third case is deliberately not a PASS. With no observed destinations the
allowlist was never exercised, so a failed capture, the wrong file uploaded, and
a genuinely quiet run all look identical, and reporting compliance there would be a
vacuous truth dressed up as a security result. **Do not read "not FAIL" as
PASS.**

The policy verdict is independent of the other flags: an allowlisted destination
on an uncommon port can still raise the "Unusual ports" flag, so a report may
show a **PASS** verdict alongside other flags.

## File format

A JSON file with an `allow` list. Each entry is either a shorthand string or an
object:

```json
{
  "allow": [
    "example.com",
    "*.github.com",
    "140.82.112.0/20",
    { "domain": "crt.sh" },
    { "ip": "91.199.212.73", "port": 443 }
  ]
}
```

Keep `ip` rules as narrow as the destination allows. A range shared by many
tenants, such as a CDN's `151.101.0.0/16`, admits every one of them, which turns
the hard gate into a formality. The CLI installs `requirements.txt` before
tracing starts, so PyPI and its CDN are not observed and need no rules.

- A **domain** matches exactly (`example.com`), or as a leading-wildcard covering
  subdomains only (`*.github.com` matches `api.github.com`, not the apex or
  `notgithub.com`).
- An **ip** is a single address or a CIDR range.
- An object rule may add a **port**, every field it declares must match.

`allow` is the only key read. There is no deny list, and an allowlist holds at
most 1000 rules. Unknown keys *inside* a rule object are rejected, but unknown
*top-level* keys are ignored silently, which cuts two ways and both surfaces
behave the same: a `deny` block written alongside `allow` is dropped without
warning and the run can still report PASS, while a document containing *only*
`deny` has no `allow` list and is rejected outright (HTTP 400 on upload, exit 2
from `egresslens check`).

Combining `domain` and `ip` in one rule does not give you an IP hard gate: a rule
that names a domain is only ever reached through domain matching, so the same IP
seen unresolved will not match it. Write the `ip` rule separately.

## How a destination is matched

A destination is expected if an `ip`/CIDR rule covers it, or, when it resolved
to one or more domains, if **every** observed domain matches a rule. That last
part fails closed on purpose: a shared IP that served both an allowed and a
disallowed name is reported as unexpected rather than passing on the allowed one.
Destinations that could not be named (unresolved IPs) match `ip`/CIDR rules only.

Because `domain` rules only match destinations that were named during
enrichment, include `egress.strace` in the upload when using them.

## Trust model

`ip`/CIDR rules match the real kernel-level destination, the address passed to
`connect()`, or to `sendto`/`sendmsg`/`sendmmsg` on an unconnected socket, and
are a hard gate. `domain` rules match the name attributed during enrichment,
which is derived from DNS answers seen in the traced process's *own* trace, so
code that is actively trying to evade the allowlist could forge that
attribution.

Treat `domain` rules as advisory (great for catching accidental or
non-adversarial egress drift) and use `ip`/CIDR rules where you need a verdict
the traced code cannot influence by choice of name.

## A verdict is only as complete as the capture

A PASS means nothing off-allowlist was *observed*, and the observation set is
bounded by the [limits](../README.md#limits). IPv6 destinations and any egress
submitted outside strace's `network` syscall class are not observed, so they
cannot raise a FAIL. An INCONCLUSIVE verdict says the capture yielded nothing to
judge at all.

Where the capture counted what it could not record, `egresslens check` reads
`run.json` from the capture directory and says so: a PASS alongside
`counts.ipv6_connects_skipped` is a PASS over the IPv4 half of the traffic. The
UI reports that same counter as "IPv6 not captured" in its Run details panel.
`run.json` is optional here – a missing or unreadable one is never an error,
since it describes the capture rather than feeding the verdict.

## Evaluating a policy locally

The verdict is not UI-only. `egresslens check` computes it from a capture
directory and returns it as an exit code, with no backend and no Docker
involved:

```bash
egresslens check egresslens-output/ --policy policy.json
egresslens run-app ./my_app --policy policy.json    # capture, then judge
```

`0` is PASS, `1` is FAIL, `3` is INCONCLUSIVE, and `2` is any input error. The
full table, including the codes a capture can return before a verdict exists, is
in [cli/README.md](../cli/README.md#exit-codes) and is not repeated here.

`2` is deliberately distinct from `1`. A gate that reported "your policy file has
a typo" the same way it reports "your app called an unlisted host" would be worse
than no gate.

With `--policy` on `run-app` or `watch`, a non-pass verdict becomes the exit
code, and a capture that failed before writing a report keeps its own status
instead: there is nothing to judge, and replacing `run-app`'s `90` for a failed
dependency install with a `2` that reads as "malformed allowlist" would point at
the wrong file.

### Enrichment, and what a PASS rests on

Passive DNS is read from the `egress.strace` sitting beside the events file, and
from any `domain`/`domain_source` fields the events already carry. `--events`
moves that default with it, so a stale trace elsewhere cannot attribute one
capture's DNS answers to another's events; `--strace` names one explicitly. **Reverse
DNS is off by default**, unlike the backend, which enables it: a gate has to be
reproducible, and reverse DNS needs egress from wherever the check runs, depends
on that host's resolver, and reads records that change. `--reverse-dns` opts in,
and the output then says how many names came from live lookups.

### Where the CLI and the UI agree, exactly

The engine is literally shared: `app.policy` and `app.enrichment` re-export
`egresslens.policy` and `egresslens.enrichment`, and a test pins that they are
the same objects. So the invariant is not "the CLI and the UI agree" but this,
which is narrower and true:

> Given the same artifacts, the same allowlist and the same enrichment settings,
> both surfaces reach the same verdict: they call the same `evaluate_policy`, and
> every value either loader accepts, it reads the same way.

Three qualifications, all of them things you can hit:

- **Enrichment defaults differ.** Reverse DNS is on for an upload and off for
  `check`, so the *default* settings are not the same settings. Pass
  `--reverse-dns` to compare like with like.
- **The CLI reads two things the upload endpoint refuses**, neither able to
  change a verdict: an events file missing `ts`, `pid`, `event`, `family` or
  `result` (the engine never reads them), and one missing `proto` (it selects a
  displayed label and is never matched against a rule). Files the UI rejects with
  a 400 can therefore still be graded here.
- **Everything else is the same file set.** Values the upload path coerces –
  a numeric string or an integral float for `dst_port`, a bool, a port outside
  1..65535, an empty `dst_ip` – are accepted here too and judged identically.
  Refusing them would have been a worse divergence than accepting them: a real
  FAIL would surface as an exit-2 error naming a field instead of a verdict
  naming a destination. `backend/test_engine_shim.py` compares the two readers
  over the values enumerated here, so a regression on any of them is caught; it
  does not enumerate every possible value.

`check` also reports how many expected destinations were covered by an `ip`/CIDR
rule and how many by a `domain` rule alone. The second number is the part of the
PASS that the traced code could have influenced by choice of name. A destination
matched by a combined `{"domain": ..., "ip": ...}` rule counts as domain-only,
which is the same point made above: such a rule is not an IP hard gate.

If an allowlist has `domain` rules and *no* destination ended up with a domain
attributed, every domain rule in it was dead, and `check` says so explicitly –
without being told, that is indistinguishable from a broken tool. It distinguishes
the two causes, because they need different fixes:

- **No trace was read**, and the events carried no attribution of their own.
  Capture `egress.strace` alongside `egress.jsonl`, or point `--strace` at it.
- **A trace was read and named none of the observed destinations.** Passive DNS
  can only name an address that appeared in a DNS *answer*, so it can never name
  the resolver the queries went to, nor anything reached without a lookup, such
  as a literal IP address. Those destinations need an `ip`/CIDR rule, no domain
  rule will ever match them. `run-app ./sample_app --args "dns example.com"` is
  exactly this case, which is worth knowing before you write your first policy.

The note is independent of the verdict, so read it as "these rules did nothing",
not as "everything failed". A domain-only allowlist does FAIL every destination
here, a mixed one can still PASS on its `ip` rules with the note attached.

### Machine-readable output

`--format json` writes the whole verdict to stdout and nothing else: the engine's
verdict dict verbatim, the unexpected-destination list (truncated at 50, as on
upload, while `unexpected_count` stays exact), enrichment counters, the notes the
text output prints, and a `capture` block holding `run.json`'s counts as they
were written. That block is the only place `udp_probes_skipped` is reported.
`schema_version` is `1`, a new key is not a breaking change.

On an input error nothing is written to stdout at all – not an error object –
and the exit code is `2`. A consumer piping to `jq` sees empty input, which is
the intended shape: there is no verdict to report.

SARIF is deliberately not emitted. SARIF results are anchored to a
`physicalLocation`, and an egress destination has no file or line, so the output
would be results with empty locations plus custom properties – poorly rendered by
GitHub code scanning and rejected outright by some consumers. It stays a pure
serializer over the same dict if a concrete consumer turns up.

## See also

- [backend/README.md](../backend/README.md): the policy API, response shape, and
  result bounds
- [docs/getting-started.md](getting-started.md#step-9-add-an-allowlist-for-a-verdict):
  writing your first policy as part of the walkthrough
- [cli/README.md](../cli/README.md): the `check` command's options and exit codes
