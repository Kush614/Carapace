"""Multimodal ingestion — turn a non-text artifact into a provenance-tagged
ContextChunk the existing action-layer engine already understands.

Why this exists: Lobster Trap's DPI is regex over *text*. An injection
painted into a screenshot is opaque pixels to it — it sails through the
conversation layer. Gemini *reads* the image; Carapace then applies its
existing injection scan + min-trust provenance to the extracted text, so
R2/R3 fire exactly as they would for a poisoned log line.

Honesty invariant (critical): **trust is bound to the source, never to
Gemini.** The model is an inspector, not an authority — it can surface a
hidden instruction, it can never *raise* a chunk's trust. If extraction
fails or returns nothing, we fail closed (treat as injection-suspected),
because an artifact we cannot read is not an artifact we can clear.

`extractor` is injectable so the engine path is unit-tested with no
network/key; the default calls Gemini vision through the same
OpenAI-compat client the agent uses (so it still flows via Lobster Trap).
"""

from __future__ import annotations

import base64
import hashlib
from typing import Callable, Optional

from .lt_shim import inspect_prompt
from .types import ContextChunk, TrustLevel

Extractor = Callable[[bytes, str], str]

_MIME = {"image": "image/png", "jpeg": "image/jpeg",
         "webp": "image/webp", "pdf": "application/pdf"}


def _sha(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def gemini_vision_extractor(media: bytes, modality: str = "image") -> str:
    """Default extractor: Gemini vision via the OpenAI-compat endpoint
    (same client/proxy path as the agent). Heavy imports are lazy so
    ``import carapace.multimodal`` stays dependency-light.
    """
    import httpx

    from .agent import AgentConfig

    cfg = AgentConfig.from_env()
    b64 = base64.b64encode(media).decode()
    mime = _MIME.get(modality, "image/png")
    body = {
        "model": cfg.model,
        "temperature": 0,
        "messages": [{"role": "user", "content": [
            {"type": "text", "text": "Transcribe ALL text visible in this "
             "image, verbatim. Output only the transcription, no commentary."},
            {"type": "image_url",
             "image_url": {"url": f"data:{mime};base64,{b64}"}},
        ]}],
    }
    headers = {
        "Authorization": f"Bearer {cfg.api_key}",
        "Content-Type": "application/json",
        "Accept-Encoding": "identity",
    }
    r = httpx.post(cfg.base_url.rstrip("/") + "/chat/completions",
                   headers=headers, json=body, timeout=cfg.timeout)
    j = r.json()
    if not isinstance(j, dict):
        raise RuntimeError(f"vision extract: unexpected response {str(j)[:200]}")
    choices = j.get("choices") or []
    return (choices[0].get("message", {}).get("content", "") if choices
            else "") or ""


def ingest(
    media: bytes,
    *,
    source_id: str,
    trust: TrustLevel,
    modality: str = "image",
    extractor: Optional[Extractor] = None,
) -> ContextChunk:
    """Extract text from ``media`` and return a provenance-tagged chunk.

    Never raises — extraction failure fails closed to injection-suspected.
    ``trust`` is taken verbatim from the caller (the source), so Gemini
    cannot launder an untrusted artifact into a trusted justification.
    """
    digest = _sha(media)
    try:
        text = (extractor or gemini_vision_extractor)(media, modality) or ""
    except Exception:
        text = ""

    if not text.strip():
        injected = True  # unreadable -> cannot clear it -> fail closed
    else:
        m = inspect_prompt(text)
        injected = bool(
            m.contains_injection_patterns
            or m.contains_role_impersonation
            or m.contains_obfuscation
        )

    return ContextChunk(
        chunk_id=source_id,
        content=text,
        trust_level=trust,           # SOURCE-bound — never raised by Gemini
        injection_suspected=injected,
        source_id=source_id,
        hash=digest,
    )
