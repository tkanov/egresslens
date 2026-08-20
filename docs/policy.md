# Egress policy reference

An egress policy is an allowlist of the destinations an app is expected to reach.
Upload one alongside a report and every observed destination is checked against
it; anything that does not match is reported as unexpected. This page is the full
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
- An object rule may add a **port**; every field it declares must match.

`allow` is the only key read. There is no deny list, and an allowlist holds at
most 1000 rules. Note that unknown keys *inside* a rule object are rejected, but
unknown *top-level* keys are currently ignored silently, so a stray `deny` block
is dropped without warning rather than failing the upload.

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

## Evaluating a policy locally

The verdict is not UI-only. `egresslens check` computes it from a capture
directory and returns it as an exit code, with no backend and no Docker
involved:

```bash
egresslens check egresslens-output/ --policy policy.json
egresslens run-app ./my_app --policy policy.json    # capture, then judge
```

| Code | Meaning |
|---|---|
| `0` | PASS |
| `1` | FAIL — at least one destination was off the allowlist |
| `2` | Error — missing or unreadable artifacts, or a malformed allowlist |
| `3` | INCONCLUSIVE — an allowlist was supplied and nothing was observed |

`2` is deliberately distinct from `1`. A gate that reported "your policy file has
a typo" the same way it reports "your app called an unlisted host" would be worse
than no gate. Note that this makes the CLI stricter than the upload path in one
place: a `deny`-only document is silently ignored on upload but is an exit-2
error here, because it contains no `allow` list.

### Enrichment, and what a PASS rests on

Passive DNS is read from the `egress.strace` sitting beside the events file, and
from any `domain`/`domain_source` fields the events already carry. `--events`
moves that default with it, so a stale trace elsewhere cannot attribute one
capture's DNS answers to another's events; `--strace` names one explicitly. **Reverse
DNS is off by default**, unlike the backend, which enables it: a gate has to be
reproducible, and reverse DNS needs egress from wherever the check runs, depends
on that host's resolver, and reads records that change. `--reverse-dns` opts in,
and the output then says how many names came from live lookups.

The parity invariant is therefore narrower than "the CLI and the UI agree":
identical artifacts and identical enrichment settings produce an identical
verdict, because both surfaces call the same `evaluate_policy`. With default
settings they can differ, and reverse DNS is the reason.

`check` also reports how many expected destinations were covered by an `ip`/CIDR
rule and how many by a `domain` rule alone. The second number is the part of the
PASS that the traced code could have influenced by choice of name. A destination
matched by a combined `{"domain": ..., "ip": ...}` rule counts as domain-only,
which is the same point made above: such a rule is not an IP hard gate.

If an allowlist has `domain` rules and *no* destination ended up with a domain
attributed, `check` says so explicitly. That case FAILs everything, and without
being told why it is indistinguishable from a broken tool. The usual cause is a
capture whose `egress.strace` was not written or not passed.

### Machine-readable output

`--format json` writes the whole verdict to stdout and nothing else: the engine's
verdict dict verbatim, the unexpected-destination list (truncated at 50, as on
upload, while `unexpected_count` stays exact), enrichment counters, and the notes
the text output prints. `schema_version` is `1`.

SARIF is deliberately not emitted. SARIF results are anchored to a
`physicalLocation`, and an egress destination has no file or line, so the output
would be results with empty locations plus custom properties — poorly rendered by
GitHub code scanning and rejected outright by some consumers. It stays a pure
serializer over the same dict if a concrete consumer turns up.

## See also

- [backend/README.md](../backend/README.md): the policy API, response shape, and
  result bounds
- [docs/getting-started.md](getting-started.md#step-9-add-an-allowlist-for-a-verdict):
  writing your first policy as part of the walkthrough
- [cli/README.md](../cli/README.md): the `check` command's options and exit codes
