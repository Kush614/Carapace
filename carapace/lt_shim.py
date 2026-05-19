"""Wire-compatible Lobster Trap shim — a pure-Python drop-in for the real
``lobstertrap.exe``, for when the Go binary or toolchain is unavailable.

It speaks the *exact same wire contract* as the genuine binary:

* an OpenAI ``/chat/completions`` reverse proxy (suffix-matched, like the
  real ``isChatCompletionEndpoint``);
* regex Deep-Prompt-Inspection over the CLAUDE.md signature families;
* the same YAML policy schema (priority + conditions + action,
  first-match-wins);
* the same injected ``_lobstertrap`` ``ResponseHeaders`` shape
  (``internal/metadata/types.go``) — so ``carapace.parse_lt_metadata`` /
  ``compose`` behave identically whether the real binary or this shim is
  in the path;
* the same JSONL audit lines ``AuditChain.append_lobstertrap`` ingests.

It is also strictly *better* on the Gemini path: it **strips** the
request ``_lobstertrap`` field before forwarding (the real binary forwards
it unstripped and Gemini rejects the unknown field), and it requests
identity encoding from the backend so metadata injection never silently
drops.

CLI parity::

    py -m carapace.lt_shim serve --policy configs/carapace_lt_policy.yaml \
        --backend https://generativelanguage.googleapis.com --listen :8080
    py -m carapace.lt_shim inspect "ignore all previous instructions"

Requires the ``api`` extra (fastapi/uvicorn) + ``policy`` (pyyaml).
"""

import argparse
import json
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Callable, Optional

# --------------------------------------------------------------------------- #
# DPI — pattern libraries (CLAUDE.md signature families, compiled once)
# --------------------------------------------------------------------------- #

_PATTERNS: dict[str, list[re.Pattern]] = {
    "injection": [re.compile(p, re.I) for p in (
        r"ignore (all |the |your )?(previous|prior|above) (instructions|prompts?)",
        r"disregard (your |the )?(rules|guidelines|safety|instructions)",
        r"forget (your |the )?(safety|content|guard|rules|instructions)",
        r"you are now (a |an |the )?\w+",
        r"\bDAN\b|jailbreak|developer mode",
        r"#{2,}\s*system|begin system prompt|<system>|<admin>",
        r"new instructions?:",
        r"reveal (your )?(system )?prompt",
    )],
    "role_impersonation": [re.compile(p, re.I) for p in (
        r"you are (now )?(an? )?(admin|root|administrator|superuser)",
        r"authorization:\s*admin", r"\bas an? admin\b", r"approved by\b",
    )],
    "credentials": [re.compile(p) for p in (
        r"sk-[A-Za-z0-9]{16,}", r"ghp_[A-Za-z0-9]{36}",
        r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+",
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        r"(?i)(aws_secret|azure_key|api[_-]?key|secret[_-]?key)\s*[=:]",
        r"(?i)(password|passwd|pwd)\s*[=:]\s*\S+",
    )],
    "pii": [re.compile(p) for p in (
        r"\b\d{3}-\d{2}-\d{4}\b",
        r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
        r"\b\d{3}[-.]\d{3}[-.]\d{4}\b",
    )],
    "system_commands": [re.compile(p, re.I) for p in (
        r"\brm\s+-rf\b", r"\bchmod\s+777\b", r"\bmkfs\b", r"\bdd\s+if=",
        r"curl[^\n|]*\|\s*(ba)?sh", r"wget[^\n|]*\|\s*sh",
        r"\bsudo\b", r"\bsu\s+-\b", r"\bnmap\b", r"\btcpdump\b", r"\bnetcat\b|\bnc\s",
        r":\(\)\s*\{",
    )],
    "exfiltration": [re.compile(p, re.I) for p in (
        r"(exfiltrate|leak|smuggle|steal)\b",
        r"(send|upload|post|curl|wget|scp)\b.{0,40}\b(to|->|→)\b",
        r"(pastebin\.com|ngrok\.io|requestbin|webhook\.site)",
    )],
    "obfuscation": [re.compile(p, re.I) for p in (
        r"[A-Za-z0-9+/]{120,}={0,2}",          # long base64 blob
        r"(\\x[0-9a-f]{2}){6,}", r"(%[0-9a-f]{2}){6,}",
        r"decode (this|the following)|base64 -d|atob\(",
    )],
    "malware_request": [re.compile(p, re.I) for p in (
        r"write (a |an )?(malware|ransomware|keylogger|rootkit|trojan|worm)",
        r"(reverse|bind) shell", r"build (an? )?exploit|0day|payload generator",
    )],
    "phishing_patterns": [re.compile(p, re.I) for p in (
        r"phishing", r"fake (login|sign[- ]?in) page", r"credential harvest",
        r"spoof(ed)? (email|domain)",
    )],
    "harm_patterns": [re.compile(p, re.I) for p in (
        r"\b(build|make|synthesize) (a )?(bomb|explosive|weapon|nerve agent)\b",
        r"how to (kill|poison|harm)\b",
    )],
    "sensitive_paths": [re.compile(p, re.I) for p in (
        r"/etc/(passwd|shadow|sudoers)", r"\.ssh/|\.gnupg/", r"\.env\b",
        r"[^\s]*secret[^\s]*", r"[^\s]*password[^\s]*", r"/root/",
    )],
    "code": [re.compile(p) for p in (
        r"```", r"\bdef \w+\(", r"\bfunction \w+\(", r"#include ", r"\bclass \w+",
        r"\bimport \w+",
    )],
}

_PATH_RE = re.compile(r"(?:/[\w.\-]+){2,}/?|[A-Za-z]:\\[\w\\.\-]+|~/[\w./\-]+")
_DOMAIN_RE = re.compile(r"\b(?:https?://)?((?:[\w-]+\.)+[a-z]{2,})\b", re.I)
_CMD_RE = re.compile(
    r"\b(rm|chmod|dd|mkfs|curl|wget|sudo|su|nmap|tcpdump|netcat|nc|isolate|"
    r"shutdown|reboot|kill)\b[^\n.;]*", re.I)

_INTENT_KEYWORDS = {
    "code_execution": ("execute", "run ", "eval", "compile", "script", "```"),
    "credential_access": ("password", "api key", "secret", "token", "credential",
                           ".ssh", "private key"),
    "network": ("isolate", "vlan", "switch", "firewall", "route", "tcpdump",
                "nmap", "spine", "network"),
    "system": ("reboot", "shutdown", "rm -rf", "chmod", "kill ", "systemctl",
               "quarantine", "throttle"),
    "file_io": ("read file", "write file", "/etc/", "open(", "cat ", "delete"),
    "data_access": ("database", "select ", "dump", "export", "query"),
    "communication": ("email", "slack", "message", "notify", "send to"),
}

# Composite risk weights (deterministic; benign ~0, blatant injection ~1).
_RISK_W = {
    "injection": 0.55, "exfiltration": 0.4, "credentials": 0.45,
    "malware_request": 0.5, "harm_patterns": 0.5, "obfuscation": 0.3,
    "role_impersonation": 0.3, "system_commands": 0.3,
    "sensitive_paths": 0.2, "phishing_patterns": 0.35, "pii": 0.25,
}


@dataclass
class PromptMetadata:
    intent_category: str = "general"
    intent_confidence: float = 0.0
    risk_score: float = 0.0
    contains_code: bool = False
    contains_credentials: bool = False
    contains_pii: bool = False
    contains_pii_request: bool = False
    contains_system_commands: bool = False
    contains_malware_request: bool = False
    contains_phishing_patterns: bool = False
    contains_role_impersonation: bool = False
    contains_exfiltration: bool = False
    contains_harm_patterns: bool = False
    contains_obfuscation: bool = False
    contains_injection_patterns: bool = False
    contains_file_paths: bool = False
    contains_sensitive_paths: bool = False
    contains_urls: bool = False
    target_paths: list[str] = field(default_factory=list)
    target_domains: list[str] = field(default_factory=list)
    target_commands: list[str] = field(default_factory=list)
    token_count: int = 0


def inspect_prompt(text: str) -> PromptMetadata:
    """Sub-millisecond regex DPI — no LLM call (mirrors the real inspector)."""
    t = text or ""
    hit = {fam: any(p.search(t) for p in pats) for fam, pats in _PATTERNS.items()}

    m = PromptMetadata(
        contains_code=hit["code"],
        contains_credentials=hit["credentials"],
        contains_pii=hit["pii"],
        contains_pii_request=bool(re.search(
            r"(give|send|share).{0,20}(ssn|social security|credit card|"
            r"personal (info|data))", t, re.I)),
        contains_system_commands=hit["system_commands"],
        contains_malware_request=hit["malware_request"],
        contains_phishing_patterns=hit["phishing_patterns"],
        contains_role_impersonation=hit["role_impersonation"],
        contains_exfiltration=hit["exfiltration"],
        contains_harm_patterns=hit["harm_patterns"],
        contains_obfuscation=hit["obfuscation"],
        contains_injection_patterns=hit["injection"],
        contains_sensitive_paths=hit["sensitive_paths"],
        token_count=max(1, len(t.split())),
    )
    paths = _PATH_RE.findall(t)
    domains = [d for d in _DOMAIN_RE.findall(t) if "." in d]
    cmds = [c.strip() for c in _CMD_RE.findall(t)]
    m.target_paths = sorted(set(paths))[:10]
    m.target_domains = sorted(set(domains))[:10]
    m.target_commands = sorted(set(cmds))[:10]
    m.contains_file_paths = bool(paths)
    m.contains_urls = bool(re.search(r"https?://", t))

    low = t.lower()
    best, best_score = "general", 0
    for cat, kws in _INTENT_KEYWORDS.items():
        s = sum(1 for k in kws if k in low)
        if s > best_score:
            best, best_score = cat, s
    m.intent_category = best
    m.intent_confidence = round(min(1.0, 0.3 + 0.2 * best_score), 4)

    risk = 0.0
    for fam, w in _RISK_W.items():
        if hit.get(fam):
            risk += w
    m.risk_score = round(min(1.0, risk), 4)
    return m


# --------------------------------------------------------------------------- #
# Policy engine — same YAML schema + match types as the real binary
# --------------------------------------------------------------------------- #


@dataclass
class RuleResult:
    action: str
    rule_name: str = ""
    deny_message: str = ""


def _match(meta: PromptMetadata, cond: dict) -> bool:
    field_name = cond["field"]
    mt = cond.get("match_type", "boolean")
    val = cond.get("value")
    cur = getattr(meta, field_name, None)
    res: bool
    if mt == "boolean":
        res = bool(cur) == bool(val)
    elif mt == "threshold":
        res = isinstance(cur, (int, float)) and float(cur) >= float(val)
    elif mt == "range":
        res = isinstance(cur, (int, float)) and float(val[0]) <= cur <= float(val[1])
    elif mt == "exact":
        res = str(cur) == str(val)
    elif mt == "prefix":
        res = str(cur).startswith(str(val))
    elif mt == "regex":
        items = cur if isinstance(cur, list) else [cur]
        res = any(re.search(str(val), str(x or "")) for x in items)
    elif mt == "contains":
        items = cur if isinstance(cur, list) else [cur]
        res = any(str(val) in str(x or "") for x in items)
    elif mt == "glob":
        items = cur if isinstance(cur, list) else [cur]
        res = any(fnmatch(str(x or ""), str(val)) for x in items)
    else:
        res = False
    return (not res) if cond.get("negate") else res


def evaluate_rules(meta: PromptMetadata, rules: list[dict],
                   default_action: str) -> RuleResult:
    """First-match-wins by descending priority (like iptables/pf)."""
    for r in sorted(rules, key=lambda x: x.get("priority", 0), reverse=True):
        conds = r.get("conditions") or []
        if conds and all(_match(meta, c) for c in conds):
            return RuleResult(str(r["action"]), str(r.get("name", "")),
                              str(r.get("deny_message", "")))
    return RuleResult(default_action, "default_action", "")


def _mismatches(declared: Optional[dict], meta: PromptMetadata) -> list[dict]:
    if not declared:
        return []
    out: list[dict] = []
    di = str(declared.get("declared_intent", "")).lower()
    # An "observe"/read-only declaration vs. an acting detected intent.
    if di and di in ("observe", "read", "monitor") and meta.intent_category in (
            "system", "network", "credential_access"):
        out.append({"field": "intent", "declared": di,
                    "detected": meta.intent_category, "severity": "critical"})
    for fld, det in (("declared_domains", meta.target_domains),
                     ("declared_commands", meta.target_commands),
                     ("declared_paths", meta.target_paths)):
        dvals = set(declared.get(fld, []) or [])
        extra = [x for x in det if x not in dvals]
        if det and extra:
            out.append({"field": fld.replace("declared_", ""),
                        "declared": sorted(dvals), "detected": extra,
                        "severity": "warning"})
    return out


# --------------------------------------------------------------------------- #
# _lobstertrap ResponseHeaders (internal/metadata/types.go contract)
# --------------------------------------------------------------------------- #


def _response_headers(request_id, verdict, declared, meta_in, ing: RuleResult,
                      meta_eg, eg: Optional[RuleResult], mism) -> dict:
    ingress = {
        "declared": declared or None,
        "detected": asdict(meta_in),
        "mismatches": mism,
        "action": ing.action,
        "rule_name": ing.rule_name,
    }
    egress = None
    if meta_eg is not None and eg is not None:
        egress = {"detected": asdict(meta_eg), "action": eg.action,
                  "rule_name": eg.rule_name}
    return {"request_id": request_id, "verdict": verdict,
            "ingress": ingress, "egress": egress}


def _deny_completion(model: str, message: str, headers: dict) -> dict:
    return {
        "id": "lobstertrap-shim-deny",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model or "lobstertrap",
        "choices": [{"index": 0, "finish_reason": "stop",
                     "message": {"role": "assistant", "content": message}}],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        "_lobstertrap": headers,
    }


def _extract_prompt(body: dict) -> str:
    parts = []
    for msg in body.get("messages", []):
        c = msg.get("content")
        if isinstance(c, str):
            parts.append(c)
        elif isinstance(c, list):
            parts.extend(str(p.get("text", "")) for p in c if isinstance(p, dict))
    return "\n".join(parts)


# --------------------------------------------------------------------------- #
# Audit (JSONL — same shape AuditChain.append_lobstertrap ingests)
# --------------------------------------------------------------------------- #


class _AuditLog:
    def __init__(self, path: Optional[str]):
        self.path = Path(path) if path else None
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, line: dict) -> None:
        if self.path:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(line, default=str) + "\n")


# --------------------------------------------------------------------------- #
# Pipeline (used by both the proxy and `inspect`)
# --------------------------------------------------------------------------- #

_NON_FORWARD = {"DENY", "QUARANTINE"}


def process(body: dict, policy: dict) -> tuple[dict, str, dict, RuleResult]:
    """Run ingress DPI + policy. Returns
    (response_headers_dict, verdict, stripped_body, ingress_result).
    """
    declared = body.pop("_lobstertrap", None)  # STRIP before any forward
    prompt = _extract_prompt(body)
    meta = inspect_prompt(prompt)
    ing = evaluate_rules(meta, policy.get("ingress_rules", []),
                         policy.get("default_action", "ALLOW"))
    mism = _mismatches(declared, meta)
    rid = "lts-" + uuid.uuid4().hex[:12]
    headers = _response_headers(rid, ing.action, declared, meta, ing,
                                None, None, mism)
    return headers, ing.action, body, ing


def make_shim_app(policy: dict, backend: str, audit_path: Optional[str] = None,
                  forward_fn: Optional[Callable] = None):
    """Build the FastAPI reverse-proxy app (drop-in for `lobstertrap serve`)."""
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse

    audit = _AuditLog(audit_path)
    app = FastAPI(title="lobstertrap-shim", version="0.1.0")

    def _default_forward(url, headers, payload):
        import httpx
        r = httpx.post(url, headers=headers, json=payload, timeout=60)
        return r.status_code, r.json()

    fwd = forward_fn or _default_forward

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "shim": True, "backend": backend}

    @app.post("/{full_path:path}")
    async def proxy(full_path: str, request: Request):
        raw = await request.body()
        try:
            body = json.loads(raw)
        except Exception:
            body = None
        if not isinstance(body, dict) or not full_path.endswith(
                "chat/completions"):
            # Non-chat / unparseable: transparent passthrough.
            url = backend.rstrip("/") + "/" + full_path
            code, data = fwd(url, _fwd_headers(request), body or {})
            return JSONResponse(data, status_code=code)

        model = str(body.get("model", "lobstertrap"))
        headers, verdict, stripped, ing = process(body, policy)
        audit.write({"request_id": headers["request_id"], "direction": "ingress",
                     "action": ing.action, "rule": ing.rule_name,
                     "detected": headers["ingress"]["detected"],
                     "mismatches": headers["ingress"]["mismatches"]})

        if verdict in _NON_FORWARD:
            msg = ing.deny_message or f"[LOBSTER TRAP] Blocked: {ing.rule_name}."
            return JSONResponse(_deny_completion(model, msg, headers))

        # Forward (Accept-Encoding: identity so we can always inject).
        url = backend.rstrip("/") + "/" + full_path
        code, data = fwd(url, _fwd_headers(request), stripped)
        if not isinstance(data, dict):
            return JSONResponse(data, status_code=code)

        # Egress DPI on the model's reply.
        reply = ""
        for ch in data.get("choices", []):
            reply += str((ch.get("message") or {}).get("content", "") or "")
        meta_eg = inspect_prompt(reply)
        eg = evaluate_rules(meta_eg, policy.get("egress_rules", []), "ALLOW")
        headers["egress"] = {"detected": asdict(meta_eg), "action": eg.action,
                             "rule_name": eg.rule_name}
        headers["verdict"] = eg.action if eg.action in _NON_FORWARD else verdict
        audit.write({"request_id": headers["request_id"], "direction": "egress",
                     "action": eg.action, "rule": eg.rule_name})

        if eg.action in _NON_FORWARD:
            msg = eg.deny_message or "[LOBSTER TRAP] Output blocked."
            return JSONResponse(_deny_completion(model, msg, headers),
                                status_code=code)
        data["_lobstertrap"] = headers
        return JSONResponse(data, status_code=code)

    def _fwd_headers(request) -> dict:
        h = {"Content-Type": "application/json", "Accept-Encoding": "identity"}
        auth = request.headers.get("authorization")
        if auth:
            h["Authorization"] = auth
        return h

    return app


# --------------------------------------------------------------------------- #
# CLI — flag-compatible with `lobstertrap serve` / `lobstertrap inspect`
# --------------------------------------------------------------------------- #


def _load_policy(path: str) -> dict:
    import yaml
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="lobstertrap-shim")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve")
    s.add_argument("--policy", required=True)
    s.add_argument("--backend", required=True)
    s.add_argument("--listen", default=":8080")
    s.add_argument("--audit-log", dest="audit_log", default=None)
    s.add_argument("--no-dashboard", action="store_true")

    i = sub.add_parser("inspect")
    i.add_argument("prompt")
    i.add_argument("--policy", default=None)

    a = ap.parse_args(argv)

    if a.cmd == "inspect":
        meta = inspect_prompt(a.prompt)
        print(json.dumps(asdict(meta), indent=2))
        if a.policy:
            pol = _load_policy(a.policy)
            res = evaluate_rules(meta, pol.get("ingress_rules", []),
                                 pol.get("default_action", "ALLOW"))
            print(f"\n  Action: {res.action}\n  Rule:   {res.rule_name}")
        return 0

    import uvicorn
    pol = _load_policy(a.policy)
    host, _, port = a.listen.rpartition(":")
    app = make_shim_app(pol, a.backend, a.audit_log)
    print(f"[lobstertrap-shim] :{port} -> {a.backend} (policy "
          f"{Path(a.policy).name}); drop-in for the real binary")
    uvicorn.run(app, host=host or "0.0.0.0", port=int(port))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
