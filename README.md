# 🦞 Carapace

> **The action-layer trust boundary that sits on top of Veea's Lobster Trap.**
> Lobster Trap guards the *conversation*. Carapace guards the *action*.

**TechEx Intelligent Enterprise Hackathon — San Jose, May 2026**
**Tracks:** Veea — *Lobster Trap* (build on top of it) · Google DeepMind — *Gemini / AI Studio*

🔴 **Live demo:** https://frontend-one-sigma-10.vercel.app
🧪 **141 tests · 138 passed · 0 failed · 3 skipped** (the 3 are live-gated: real-cluster + live-Gemini-vision) — real run committed: [`docs/TEST_RESULTS.txt`](docs/TEST_RESULTS.txt) · [`docs/test-results.xml`](docs/test-results.xml) (JUnit) · ✅ proven live end-to-end (real Gemini → real Lobster Trap → Carapace)

[![real-k8s](https://github.com/Kush614/Carapace/actions/workflows/real-k8s.yml/badge.svg)](https://github.com/Kush614/Carapace/actions/workflows/real-k8s.yml)
☸️ **Real-cluster proof runs in CI** — every push spins a real `kind`
cluster with Calico, applies the edge fabric, and asserts the token-gated
executor's deny-all NetworkPolicy *actually severs cross-site traffic*
then heals (`tests/test_k8s_integration.py`, `.github/workflows/real-k8s.yml`).
Why CI and not a laptop: a real cluster needs Docker/WSL2/admin; this is
the reproducible, publicly verifiable substitute.

---

## 1. The problem

AI agents now take real actions on production infrastructure — migrate VMs,
isolate VLANs, quarantine nodes. The guardrails have not kept up. A single
**poisoned log line** ingested as context can trick an agent into
`isolate(spine-switch-sj-01)` — a self-inflicted outage the agent authorized
itself, with no audit trail of *why*.

Veea's **Lobster Trap** inspects the *conversation* (every prompt/response)
and stops injection at that layer. But a clean-looking conversation can still
end in a destructive action. **Nothing inspects the action itself** — its
declared-vs-detected intent, the trust of the data that justified it, or its
blast radius.

## 2. What Carapace is

Carapace is the policy enforcement layer **between an agent's reasoning and
its tool execution**. It consumes Lobster Trap's verdict and adds an
*action-layer* decision: declared-vs-detected intent, source provenance, and
infrastructure blast radius, then issues a **single-use execution token**. No
token → the executor never runs.

> **Veea's framing: "Lobster Trap is the floor, not the ceiling."**
> Carapace is literally what you build on it. We run the *real* Lobster Trap
> binary as the floor and compose our action layer on top — defense in depth.
>
> Imagine a robot helper that can flip real switches
in a power station. One day someone slips a fake note into the robot's mailbox
that says *"turn everything off!"* — and the robot almost believes it. Carapace
is the careful grown-up standing at the door. Before the robot flips any switch
it asks: *who really asked for this? how much could it break? did the idea come
from somewhere we trust?* If anything looks wrong it stops the robot, locks the
bad request in a box, and writes down exactly what happened so no one can fib
about it later. We build this so one sneaky note can't black out the whole town.

## 3. Architecture

```
                 +-------------------------- conversation layer --+
 Gemini agent -->|  real lobstertrap.exe  (Veea, MIT, Go)         |--> Gemini
 (OpenAI SDK,    |  DPI on every prompt/response, P4 YAML policy,  |   OpenAI-compat
  base_url =     |  emits _lobstertrap{verdict,detected,mismatches}|   API
  :8080/v1beta)  +-------------------------------+-----------------+
                                                 | _lobstertrap metadata
 IntentEnvelope ---------------------------------+  (declared vs detected)
 {intent,tool,args,justification,source_signals} |
                                                 v
        +-------------------- action layer -- CARAPACE -----------------+
        | build_inputs:  classify detected_intent . blast_radius .      |
        |                resolve provenance (min-trust, fail-closed)    |
        | fold:          fold Lobster Trap verdict in  (MONOTONE -- can |
        |                only tighten, never loosen the decision)       |
        | decide:        pure rule matrix R1-R9  (deterministic)        |
        | escalate:      R2 DENY -> QUARANTINE when LT corroborates     |
        +---------------+-----------------------------------+-----------+
            ALLOW -> single-use 5s token -> mock executor   DENY / QUARANTINE
            HUMAN_REVIEW -> human gate (reviewer in audit)   -> no token, no exec
                                          |
                                          v
                  unified SHA-256 hash-chained audit (NDJSON)
            interleaves Lobster Trap lines + Carapace decisions, in order
```

The composition is **monotone toward caution**: Lobster Trap can only ever
make Carapace *more* restrictive. Remove Lobster Trap and Carapace degrades
gracefully to standalone enforcement.

## 4. Sponsor usage (what judges should look at)

### 🦞 Veea — Lobster Trap  (`github.com/veeainc/lobstertrap`, MIT)

| How we used it | Where |
|---|---|
| **Built the real binary from source** — no prebuilt release exists, no Go toolchain on the machine; installed Go via no-admin MSI extract and `go build` the genuine binary | `bin/lobstertrap.exe` (v0.1.0) |
| **Run it as the conversation-layer floor** in front of Gemini | `demo/run_live.py`, README §6 |
| **Forked Veea's `default_policy.yaml`** — every upstream security rule preserved verbatim, tuned for the edge-ops agent + Gemini backend | `configs/carapace_lt_policy.yaml` |
| **Consume the `_lobstertrap` contract** (parsed against the real `internal/metadata/types.go`) and fold it into the action decision | `carapace/lobstertrap.py` |
| **Wire-compatible Python shim** — drop-in stand-in proving we understood the contract; also fixes a real bug we found (binary forwards the request `_lobstertrap` field unstripped; Gemini rejects unknown fields) | `carapace/lt_shim.py` |
| **Two real integration fixes** documented: host-only `--backend` (the proxy's Director only swaps scheme/host); `Accept-Encoding: identity` so the proxy can inject metadata into Gemini's gzipped responses | `carapace/agent.py` docstring |

### ✨ Google — Gemini / AI Studio

| How we used it | Where |
|---|---|
| **Gemini drives the agent** — `gemini-flash-latest` reasons over telemetry/logs and emits a structured Carapace `IntentEnvelope` | `carapace/agent.py` |
| **Via the Gemini OpenAI-compatibility endpoint** (`generativelanguage.googleapis.com/v1beta/openai`) so it speaks through the Lobster Trap proxy unchanged | `carapace/agent.py`, `configs/carapace_lt_policy.yaml` (allowlisted) |
| **Proven live**: in Scenario A, Gemini itself proposed `migrate_vm(...)`; in Scenario C the poisoned turn was caught and quarantined | `demo/run_live.py` |
| Key read from `GEMINI_API_KEY` env only — never committed | repo contains no secrets (verified) |

## 5. How the decision works — rule matrix (spec §6.1, first match wins)

| # | Condition | Decision |
|---|---|---|
| R1 | detected ≠ declared intent | DENY |
| R2 | injection-tainted + `remediate_*` | DENY → **QUARANTINE** if Lobster Trap corroborates |
| R3 | untrusted provenance + destructive | DENY |
| R4 | blast radius ∈ {site, region} | HUMAN_REVIEW |
| R5 | destructive + blast ∈ {vlan, node} | HUMAN_REVIEW |
| R6 | semi-trusted + destructive | HUMAN_REVIEW |
| R7 | reversible + provenance ≠ untrusted | ALLOW |
| R8 | observe / recommend | ALLOW |
| R9 | default | DENY (fail-closed) |

`decide()` is a **pure, deterministic** function pinned by a ruleset hash —
every historical decision replays exactly. Any classifier error, unresolved
citation, or empty justification fails closed.

## 6. Run it

**Offline demo (no key, deterministic, bulletproof):**
```powershell
py demo\run_demo.py            # Scenarios A-D
py -m pytest                   # 138 passed, 3 skipped (Test evidence below)
```

**Live stack (real Gemini through the real binary):**
```powershell
bin\lobstertrap.exe serve --backend https://generativelanguage.googleapis.com `
  --listen :8080 --policy configs\carapace_lt_policy.yaml --no-dashboard
$env:GEMINI_API_KEY="..."     # never committed
py -m uvicorn carapace.api:app --port 8088
py demo\run_live.py
```

**Frontend (3D, Gumroad-styled, self-contained):**
```powershell
py -m http.server 5500 --directory frontend   # or just open the Vercel URL
```
No Go? `py -m carapace.lt_shim serve ...` is a byte-compatible drop-in for
`bin\lobstertrap.exe serve ...`.

## 6.5 Test evidence (real, generated — not hand-typed)

Full console output and JUnit XML from an actual run are committed:
[`docs/TEST_RESULTS.txt`](docs/TEST_RESULTS.txt) ·
[`docs/test-results.xml`](docs/test-results.xml). The same numbers are
served to the UI as [`frontend/test-results.json`](frontend/test-results.json)
and shown in the "Test evidence" section of the **How it works** panel on
the live site. Regenerate any time:

```powershell
py -m pytest -v --junit-xml=docs/test-results.xml | Tee-Object docs/TEST_RESULTS.txt
```

**Latest run — 138 passed, 0 failed, 0 errors, 3 skipped (0.91s).** The 3
skipped are the *live-gated* tests that need real infra/keys and run only
where available: `test_k8s_integration.py` (×2, real kind cluster, runs
in CI) and the live Gemini-vision case in `test_multimodal.py` (×1). They
are skipped — never silently passed — so the count stays honest.

| Test file | Tests | Passed | Skipped |
|---|--:|--:|--:|
| `tests/test_lobstertrap.py` | 19 | 19 | 0 |
| `tests/test_decision_engine.py` | 15 | 15 | 0 |
| `tests/test_intent_classifier.py` | 14 | 14 | 0 |
| `tests/test_blast_radius.py` | 13 | 13 | 0 |
| `tests/test_lt_shim.py` | 11 | 11 | 0 |
| `tests/test_demo_api.py` | 9 | 9 | 0 |
| `tests/test_agent.py` | 8 | 8 | 0 |
| `tests/test_executor_k8s.py` | 8 | 8 | 0 |
| `tests/test_multimodal.py` | 8 | 7 | 1 |
| `tests/test_api.py` | 7 | 7 | 0 |
| `tests/test_audit.py` | 6 | 6 | 0 |
| `tests/test_policy.py` | 6 | 6 | 0 |
| `tests/test_scenarios.py` | 6 | 6 | 0 |
| `tests/test_provenance.py` | 5 | 5 | 0 |
| `tests/test_types.py` | 4 | 4 | 0 |
| `tests/test_k8s_integration.py` | 2 | 0 | 2 |
| **TOTAL** | **141** | **138** | **3** |

Coverage spans the pure engine (R1–R9), Lobster Trap composition + monotone
fold, audit hash-chain tamper-detection, the FastAPI gate, the policy pack,
the Gemini agent, the wire-compatible shim, and the real K8s executor
(token-gating, command construction, gate logic).

## 7. Demo scenarios (verified, A–D)

| | Scenario | Outcome |
|---|---|---|
| **A** | Legit intra-site migration, trusted telemetry | **ALLOW [R7]** → token → executed (Carapace is transparent for real work) |
| **B** | Poisoned log, trust layer **off** | tool runs unchecked → site dark, **~$47k/min** |
| **C** | *Same* poisoned log, full stack | Lobster Trap flags injection; Carapace escalates **DENY → QUARANTINE [R2]**; executor never called; **$0** |
| **D** | Real spine fault, trusted telemetry, site radius | **HUMAN_REVIEW [R4]** → `alice@ops` approves → executed; **reviewer identity in the audit chain** |

## 8. Tech stack

| Layer | Tech |
|---|---|
| Conversation security | **Veea Lobster Trap** (Go, MIT) — built from source |
| Agent reasoning | **Google Gemini** `gemini-flash-latest` via OpenAI-compat |
| Core engine | Python 3.13, **zero runtime deps**, pure & deterministic |
| Action-gate service | FastAPI + Pydantic + single-use tokens |
| Audit | Append-only NDJSON, SHA-256 hash chain (tamper-evident) |
| Policy | YAML, two-layer (conversation + action), drift-verified vs engine |
| Frontend | Single-file HTML + Three.js (self-hosted) — Gumroad neo-brutalist 3D |
| Deploy | Vercel (static) |
| Tests | pytest — **141: 138 passed, 0 failed, 3 live-gated skipped** (real run in `docs/`; engine · composition · audit · API · policy · agent · shim · K8s executor · demo-API · multimodal · chatbot) |

## 9. Repo layout

```
carapace/
  types.py            enums + frozen data types (no I/O)
  decision_engine.py  decide() R1-R9 + build_inputs/assemble_record seam
  intent_classifier.py / blast_radius.py   argument-aware classifiers
  provenance.py       min-trust resolution, fail-closed
  lobstertrap.py      parse _lobstertrap . monotone fold . compose() . QUARANTINE
  audit.py            append-only SHA-256 hash-chained unified trail
  policy.py           policy-pack loader + engine drift verifier
  api.py              FastAPI action-gate (single-use execution tokens, CORS)
  agent.py            Gemini agent through the Lobster Trap proxy
  lt_shim.py          wire-compatible pure-Python Lobster Trap drop-in
configs/              two-layer policy pack (LT fork + action matrix)
demo/                 run_demo.py (offline A-D) · run_live.py (full live)
frontend/             index.html (3D UI) + self-hosted Three.js + vercel.json
bin/lobstertrap.exe   the REAL Veea binary, built here from MIT source
tests/                141 tests · 138 pass · 3 live-gated (docs/TEST_RESULTS.txt)
```

## 10. Audit a regulator could read

Every decision — conversation-layer (Lobster Trap) and action-layer
(Carapace) — is one NDJSON line, SHA-256 chained to the previous. Any edit,
deletion, or reorder breaks the chain (`AuditChain.verify()`). Human approvals
record the reviewer's identity. This is the "audit trail a regulator could
read" the brief asks for.

## Credits & license

Built **on top of** [Veea Lobster Trap](https://github.com/veeainc/lobstertrap)
(MIT) — the conversation-layer DPI proxy this project extends, included here
as `bin/lobstertrap.exe` built from that MIT source. Reasoning by
**Google Gemini** via the Gemini OpenAI-compatibility endpoint. Project code
MIT.
