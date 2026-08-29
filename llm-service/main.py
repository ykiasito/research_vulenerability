"""LLM integration microservice for Stage1 Tier2/Tier3 identification and Stage4
vulnerability research (see the implementation plan). A thin wrapper around the
Anthropic Messages API — all Claude-specific logic lives here so the Spring Boot
backend never depends on an LLM SDK directly.

Every endpoint takes the caller's own Claude API key in the request body (never
stored here — see user_secrets in the backend, which is the only place keys are
persisted, AES-GCM encrypted). Requests are per-item and synchronous; the plan's
Batch API cost optimization (50% discount) is deferred to a later pass since it
changes the calling shape to submit-then-poll — not implemented here.

Model: Haiku 4.5 (`claude-haiku-4-5`) for all three endpoints, per the plan's cost
target. Haiku 4.5 is NOT in the model set that supports the dynamic-filtering
`web_search_20260209` tool (Opus 5/4.8/4.7/4.6, Sonnet 5, Sonnet 4.6 only) — Tier3
and Stage4 use the basic `web_search_20250305` variant instead.
"""

import json
import logging
import os
from logging.handlers import RotatingFileHandler

import anthropic
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="vulncheck-llm-service")

# Configured explicitly (own handlers, not relying on uvicorn's/root logging config) so these
# outcome logs are guaranteed to show up regardless of how uvicorn is invoked. Never logs api_key
# or full response text — only the decision-relevant fields, for auditing what each tier actually
# did without needing to query the DB.
#
# Writes to console AND a rotating file. The file directory is bind-mounted to the host via
# docker-compose.yml so log files survive container restarts/recreates and are readable directly
# from the host filesystem, not just via `docker compose logs`. Set LOG_FILE="" to disable file
# logging (e.g. for local `uvicorn main:app` runs without the volume mounted).
logger = logging.getLogger("vulncheck.llm")
logger.setLevel(logging.INFO)
if not logger.handlers:
    _formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    _stream_handler = logging.StreamHandler()
    _stream_handler.setFormatter(_formatter)
    logger.addHandler(_stream_handler)

    _log_file = os.environ.get("LOG_FILE", "/var/log/app/llm-service.log")
    if _log_file:
        os.makedirs(os.path.dirname(_log_file), exist_ok=True)
        _file_handler = RotatingFileHandler(_log_file, maxBytes=10 * 1024 * 1024, backupCount=14)
        _file_handler.setFormatter(_formatter)
        logger.addHandler(_file_handler)

MODEL = "claude-haiku-4-5"


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


def _client(api_key: str) -> anthropic.Anthropic:
    return anthropic.Anthropic(api_key=api_key)


def _raise_for_anthropic_error(e: Exception) -> None:
    """Maps Anthropic SDK exceptions to HTTP responses for the backend to handle.
    Order matters: most-specific first (see the claude-api skill's error-handling
    guidance) — a bare APIStatusError catch would blur retryable vs not.
    """
    logger.warning("Claude API call failed: %s: %s", type(e).__name__, e)
    if isinstance(e, anthropic.AuthenticationError):
        raise HTTPException(status_code=401, detail="Invalid Claude API key") from e
    if isinstance(e, anthropic.PermissionDeniedError):
        raise HTTPException(status_code=403, detail="Claude API key lacks required permissions") from e
    if isinstance(e, anthropic.RateLimitError):
        raise HTTPException(status_code=429, detail="Claude API rate limit exceeded") from e
    if isinstance(e, anthropic.APIStatusError):
        if e.status_code >= 500:
            raise HTTPException(status_code=502, detail="Claude API server error") from e
        raise HTTPException(status_code=400, detail=f"Claude API rejected the request: {e.message}") from e
    if isinstance(e, anthropic.APIConnectionError):
        raise HTTPException(status_code=503, detail="Could not reach the Claude API") from e
    raise HTTPException(status_code=500, detail="Unexpected error calling the Claude API") from e


def _final_text_block(content: list) -> str | None:
    """output_config.format guarantees the last text block is valid JSON; earlier
    blocks may be server_tool_use / web_search_tool_result when a web_search tool
    was attached. Scan from the end rather than assuming a fixed position.
    """
    for block in reversed(content):
        if block.type == "text":
            return block.text
    return None


class UsageInfo(BaseModel):
    """Real Claude API usage for one call, reported back so the Java backend's
    JobCostBudgetService can reconcile its worst-case reservation down to actual spend, instead of
    tracking a job's budget purely against flat per-tier estimates. web_search_requests is 0 for
    endpoints that never attach the web_search tool (disambiguate)."""

    input_tokens: int
    output_tokens: int
    web_search_requests: int = 0


def _count_web_searches(usage, content: list) -> int:
    """Number of web_search calls Anthropic actually billed for, from
    response.usage.server_tool_use.web_search_requests — the billing-authoritative count.

    Previously this counted web_search_tool_result content blocks instead, which
    double/triple-counted: Anthropic returns a web_search_tool_result block for a search that
    hit an error too (e.g. error_code="max_uses_exceeded" once max_uses is reached), and those
    error blocks are not billed. That bug inflated Stage4's measured cost by ~2.57x in the
    2026-08-29 job 185 cost test (see docs/spec/nfr-status-2026-08.md's cost section) even
    though max_uses=1 there — reported search counts of 2-4 turned out to be mostly unbilled
    error blocks, not real searches.

    Falls back to counting successful web_search_tool_result blocks in `content` — i.e. blocks
    whose `.content` is a list (a list of web_search_result items), not the error shape (a single
    error object) — if server_tool_use is missing from the response, e.g. an older anthropic SDK
    version that predates this field (see llm-service/requirements.txt's pinned version). This is
    NOT the same buggy counting method described above: that bug counted ALL
    web_search_tool_result blocks including error ones; this fallback counts only the
    non-error/successful ones. Verified against job 187's real data (2026-08-29): the number of
    successful blocks matched the actual billed count of 1 exactly, so this does not inflate cost.
    Deliberately does NOT fall back to 0 — an earlier version of this function did, which is a
    fail-open cost-cap bypass: it would silently report "0 web searches" for every Stage4/Tier3
    call if the SDK ever stopped populating server_tool_use, causing `reconcile` to refund nearly
    the entire worst-case reservation and making the job budget effectively unlimited, defeating
    the entire point of this cost-cap mechanism.
    """
    server_tool_use = getattr(usage, "server_tool_use", None)
    if server_tool_use is None:
        logger.warning(
            "response.usage.server_tool_use missing from Claude API response — falling back to "
            "counting successful web_search_tool_result content blocks. Check that the anthropic "
            "SDK version (llm-service/requirements.txt) actually supports this field."
        )
        return sum(
            1
            for block in content
            if getattr(block, "type", None) == "web_search_tool_result" and isinstance(block.content, list)
        )
    return getattr(server_tool_use, "web_search_requests", 0)


def _extract_source_urls(content: list) -> list[str]:
    urls: list[str] = []
    for block in content:
        if block.type != "web_search_tool_result":
            continue
        result = block.content
        if not isinstance(result, list):
            # Error shape: a single web_search_tool_result_error object, not a list
            # of results (see the claude-api skill's server-tool-errors pitfall).
            continue
        for item in result:
            if getattr(item, "type", None) == "web_search_result" and item.url:
                urls.append(item.url)
    return urls


# --- Tier2: LLM disambiguation among Stage1 Tier1's static candidates ------------

class Candidate(BaseModel):
    ecosystem: str | None = None
    package_name: str | None = None
    cpe: str | None = None
    purl: str | None = None
    source: str


class DisambiguateRequest(BaseModel):
    api_key: str
    product_name: str
    version: str
    vendor: str | None = None
    usage_text: str
    candidates: list[Candidate] = Field(min_length=1)


class DisambiguateResponse(BaseModel):
    matched: bool
    selected_index: int | None = None
    confidence: float
    reasoning: str
    usage: UsageInfo


DISAMBIGUATE_SCHEMA = {
    "type": "object",
    "properties": {
        "matched": {"type": "boolean"},
        "selected_index": {
            "type": ["integer", "null"],
            "description": "0-based index into the provided candidates array, or null if none match.",
        },
        "confidence": {"type": "number", "description": "0.0 to 1.0"},
        "reasoning": {"type": "string"},
    },
    "required": ["matched", "selected_index", "confidence", "reasoning"],
    "additionalProperties": False,
}


@app.post("/v1/identify/disambiguate", response_model=DisambiguateResponse)
def disambiguate(req: DisambiguateRequest) -> DisambiguateResponse:
    """Tier2: pick the single best candidate Tier1 already found — this endpoint
    never invents a new ecosystem/package/cpe, only selects an index, so the
    backend's own (already-validated) candidate data is what actually gets used.
    """
    candidates_text = "\n".join(
        f"[{i}] ecosystem={c.ecosystem} package_name={c.package_name} cpe={c.cpe} purl={c.purl} source={c.source}"
        for i, c in enumerate(req.candidates)
    )
    user_content = (
        f"Product name (as entered by the user): {req.product_name}\n"
        f"Version: {req.version}\n"
        f"Vendor (as entered, may be blank): {req.vendor or '(not provided)'}\n"
        f"Usage / context text: {req.usage_text}\n\n"
        f"Candidates found by static lookup (package registries / CPE dictionary):\n{candidates_text}\n\n"
        "Note: any cpe field has its version segment masked as '*' — this system substitutes the "
        "real version separately downstream, so judge candidates only on vendor/product identity "
        "against the usage text, never on version number.\n\n"
        "Which candidate (if any) is the correct match for this product? Respond only via the JSON schema."
    )

    try:
        response = _client(req.api_key).messages.create(
            model=MODEL,
            max_tokens=1024,
            system=(
                "You identify which of several candidate software package/CPE matches (found by "
                "static lookup) actually corresponds to a product a user is about to install. Only "
                "select among the given candidates — never invent a new one. If none plausibly match, "
                "set matched=false."
            ),
            messages=[{"role": "user", "content": user_content}],
            output_config={"format": {"type": "json_schema", "schema": DISAMBIGUATE_SCHEMA}},
        )
    except Exception as e:
        _raise_for_anthropic_error(e)

    text = _final_text_block(response.content)
    if text is None:
        raise HTTPException(status_code=502, detail="Claude API returned no text content")

    data = json.loads(text)
    if data.get("selected_index") is not None and not (0 <= data["selected_index"] < len(req.candidates)):
        raise HTTPException(status_code=502, detail="Claude selected an out-of-range candidate index")
    usage = UsageInfo(input_tokens=response.usage.input_tokens, output_tokens=response.usage.output_tokens)
    logger.info(
        "disambiguate product=%r version=%r candidates=%d -> matched=%s selected_index=%s confidence=%s "
        "usage=%s",
        req.product_name, req.version, len(req.candidates),
        data.get("matched"), data.get("selected_index"), data.get("confidence"), usage,
    )
    return DisambiguateResponse(**data, usage=usage)


# --- Tier3: LLM + web_search to resolve a product's real vendor/name ------------

class WebSearchIdentifyRequest(BaseModel):
    api_key: str
    product_name: str
    version: str
    vendor: str | None = None
    usage_text: str
    enabled_ecosystems: list[str] = []


class EcosystemCandidate(BaseModel):
    ecosystem: str
    package_name: str


class PlatformHint(BaseModel):
    platform: str | None = None
    identifier: str | None = None
    note: str | None = None


class WebSearchIdentifyResponse(BaseModel):
    found: bool
    official_vendor: str | None = None
    official_product_name: str | None = None
    reasoning: str
    source_urls: list[str] = []
    ecosystem_candidates: list[EcosystemCandidate] = []
    platform_hint: PlatformHint | None = None
    usage: UsageInfo


def _web_search_identify_schema(enabled_ecosystems: list[str]) -> dict:
    """Built per-request (not a module constant) so the ecosystem_candidates.ecosystem field can
    be constrained via enum to exactly the ecosystems the backend has enabled — the model can
    never propose an ecosystem the backend has no adapter for.
    """
    ecosystem_property: dict = {"type": "string"}
    if enabled_ecosystems:
        ecosystem_property["enum"] = enabled_ecosystems
    return {
        "type": "object",
        "properties": {
            "found": {"type": "boolean"},
            "official_vendor": {"type": ["string", "null"]},
            "official_product_name": {"type": ["string", "null"]},
            "reasoning": {
                "type": "string",
                "description": (
                    "If found=true, a brief note on how you identified it. If found=false, this is "
                    "shown directly to the end user as the reason nothing could be found — write it "
                    "in Japanese, one concise sentence, stating your best guess at *why* rather than "
                    "just 'not found'. Common reasons: firmware or an embedded/device product with "
                    "no public software registry (e.g. 'ルーター等のファームウェアと見られ、公開レジストリには存在しません'); "
                    "a commercial/proprietary product with no public package listing (e.g. "
                    "'商用ライセンス製品と見られ、公開の入手元が見つかりませんでした'); an internal-only or "
                    "custom-built tool; or the product name/version as given does not match any real "
                    "software you could find (e.g. a likely typo). Give your best-guess reason even "
                    "when not fully certain — say so is a guess, but always give one instead of a "
                    "generic 'could not find information'."
                ),
            },
            "ecosystem_candidates": {
                "type": "array",
                "description": (
                    "Zero or more guesses at the exact package-registry ecosystem and package "
                    "name/id this product is published under, only using ecosystems from the "
                    "allowed list. Leave empty if not reasonably confident of an exact "
                    "identifier — a wrong guess is worse than none, since the backend queries "
                    "the real registry directly with whatever is given here."
                ),
                "items": {
                    "type": "object",
                    "properties": {
                        "ecosystem": ecosystem_property,
                        "package_name": {"type": "string"},
                    },
                    "required": ["ecosystem", "package_name"],
                    "additionalProperties": False,
                },
            },
            "platform_hint": {
                "type": ["object", "null"],
                "description": (
                    "If this product is NOT published under one of the enabled_ecosystems, but is "
                    "still published through some other recognizable distribution channel with its "
                    "own identifier scheme (a VS Code Marketplace extension id like "
                    "'publisher.extension-name', a Chrome Web Store extension id, a Docker Hub "
                    "image name, a Homebrew formula, a Linux distro package name, an App Store id, "
                    "etc.), provide that identifier here so a human can look it up / verify it "
                    "manually — this app has no automated adapter for that channel. Null if no "
                    "such identifier is known or applicable."
                ),
                "properties": {
                    "platform": {
                        "type": ["string", "null"],
                        "description": "Name of the distribution channel, e.g. 'VS Code Marketplace'",
                    },
                    "identifier": {
                        "type": ["string", "null"],
                        "description": "The exact identifier/slug on that platform, e.g. 'ms-python.python' — keep this as-is, do not translate it",
                    },
                    "note": {
                        "type": ["string", "null"],
                        "description": (
                            "One sentence in Japanese, phrased as a confirmation question for the "
                            "human to verify — not a confident statement of fact. This identifier "
                            "is a guess from web search, not a certainty. E.g. "
                            "'これで合っていますか？VS Code Marketplaceで識別子をご確認ください' "
                            "rather than stating it as an established fact."
                        ),
                    },
                },
                "required": ["platform", "identifier", "note"],
                "additionalProperties": False,
            },
        },
        "required": [
            "found", "official_vendor", "official_product_name", "reasoning",
            "ecosystem_candidates", "platform_hint",
        ],
        "additionalProperties": False,
    }


@app.post("/v1/identify/web-search", response_model=WebSearchIdentifyResponse)
def web_search_identify(req: WebSearchIdentifyRequest) -> WebSearchIdentifyResponse:
    """Tier3: static lookup found zero candidates for this product name — often a
    marketplace/store listing name that differs from the vendor's real product name. Resolves the
    official vendor/product name (backend re-queries Tier1 with it), and may additionally propose
    exact package-registry identifiers in ecosystem_candidates when confident — the backend
    verifies each against the real registry before trusting it, so this is not a "trust the LLM
    blindly" path, just a way to skip the "hope the official name equals the registry slug" gap.
    """
    ecosystems_text = ", ".join(req.enabled_ecosystems) if req.enabled_ecosystems else "(none configured)"
    user_content = (
        f"Product name as listed (possibly a marketplace/store name, not the vendor's own name): "
        f"{req.product_name}\n"
        f"Version: {req.version}\n"
        f"Vendor (as entered, may be blank): {req.vendor or '(not provided)'}\n"
        f"Usage / context text: {req.usage_text}\n\n"
        f"Package-registry ecosystems this system can directly query: {ecosystems_text}\n\n"
        "Search the web to find the actual vendor name and official product name for this "
        "software. Additionally, if you are confident this software is published as a package "
        "under one of the listed ecosystems (its registry package name/id may differ from the "
        "product name above), include it in ecosystem_candidates — use ONLY ecosystem values "
        "from the list given, and only when reasonably confident of the exact identifier. "
        "If it is NOT published under any of those ecosystems but you can still identify a "
        "concrete identifier on some other distribution channel (e.g. a VS Code Marketplace "
        "extension id, a Chrome Web Store extension id, a Docker Hub image, a Homebrew formula, "
        "a Linux distro package name), set platform_hint so a human can look it up manually — "
        "this app has no automated adapter for that channel. This app's users are Japanese "
        "speakers: write platform_hint.note in Japanese, phrased as a question asking the human "
        "to confirm the identifier is correct (it's a web-search guess, not a certainty) — not a "
        "confident statement of fact. Keep platform_hint.identifier as the literal, untranslated "
        "identifier. Respond only via the JSON schema."
    )

    try:
        response = _client(req.api_key).messages.create(
            model=MODEL,
            max_tokens=1024,
            system=(
                "You resolve marketplace/store listing names to the vendor's actual, official product "
                "name using web search, for products that plain package-registry lookups couldn't find. "
                "When possible, also identify the exact package-registry identifier so the caller can "
                "query that registry directly instead of guessing from the official name alone."
            ),
            messages=[{"role": "user", "content": user_content}],
            tools=[{"type": "web_search_20250305", "name": "web_search", "max_uses": 2}],
            output_config={"format": {"type": "json_schema", "schema": _web_search_identify_schema(req.enabled_ecosystems)}},
        )
    except Exception as e:
        _raise_for_anthropic_error(e)

    text = _final_text_block(response.content)
    if text is None:
        raise HTTPException(status_code=502, detail="Claude API returned no text content")

    data = json.loads(text)
    usage = UsageInfo(
        input_tokens=response.usage.input_tokens,
        output_tokens=response.usage.output_tokens,
        web_search_requests=_count_web_searches(response.usage, response.content),
    )
    result = WebSearchIdentifyResponse(**data, source_urls=_extract_source_urls(response.content), usage=usage)
    logger.info(
        "web_search_identify product=%r version=%r -> found=%s official_vendor=%r official_product_name=%r "
        "urls=%d ecosystem_candidates=%s platform_hint=%s usage=%s",
        req.product_name, req.version, result.found, result.official_vendor,
        result.official_product_name, len(result.source_urls),
        [(c.ecosystem, c.package_name) for c in result.ecosystem_candidates],
        (result.platform_hint.platform, result.platform_hint.identifier) if result.platform_hint else None,
        usage,
    )
    return result


# --- Stage4: LLM + web_search final fallback for vulnerability research --------

class WebSearchVulnFinding(BaseModel):
    identifier: str
    severity: str | None = None
    description: str
    citation_url: str
    fixed_version: str | None = None


class WebSearchResearchRequest(BaseModel):
    api_key: str
    product_name: str
    version: str
    vendor: str | None = None
    ecosystem: str | None = None
    package_name: str | None = None


class WebSearchResearchResponse(BaseModel):
    findings: list[WebSearchVulnFinding] = []
    usage: UsageInfo


WEB_SEARCH_RESEARCH_SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "identifier": {
                        "type": "string",
                        "description": "CVE/GHSA ID if known, otherwise a short descriptive identifier.",
                    },
                    "severity": {"type": ["string", "null"]},
                    "description": {"type": "string"},
                    "citation_url": {"type": "string"},
                    "fixed_version": {
                        "type": ["string", "null"],
                        "description": "The version this is fixed in, if a credible source states one. Null if unknown/no fix yet.",
                    },
                },
                "required": ["identifier", "severity", "description", "citation_url", "fixed_version"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["findings"],
    "additionalProperties": False,
}


@app.post("/v1/research/web-search", response_model=WebSearchResearchResponse)
def web_search_research(req: WebSearchResearchRequest) -> WebSearchResearchResponse:
    """Stage4: last-resort fallback — only called when NVD/OSV/GHSA (Stage2) and
    the NVD keyword fallback (Stage3) found nothing for an identified product.
    max_uses capped at 1 (reduced 2026-08-25 from 2 per the senior-engineer cost review — Stage4
    web-search research alone accounted for 79% of measured per-item AI spend; needs empirical
    A/B validation against the pre-change ~15% Stage4 hit rate before trusting this long-term).
    """
    user_content = (
        f"Product: {req.product_name} (vendor: {req.vendor or 'unknown'}), version {req.version}\n"
        f"Ecosystem: {req.ecosystem or 'unknown'}, package name: {req.package_name or 'unknown'}\n\n"
        "Structured vulnerability databases (NVD, OSV.dev, GitHub Security Advisories) found nothing "
        "for this exact product/version. Search the web for official vendor advisories, security "
        "bulletins, or release notes that mention known vulnerabilities for this product at "
        "approximately this version. If you find none, return an empty findings list — do not guess "
        "or report vulnerabilities you are not reasonably confident apply to this version. For each "
        "finding, if a credible source states which version fixes it, include that in "
        "fixed_version — otherwise leave it null rather than guessing. Respond only via the JSON "
        "schema."
    )

    try:
        response = _client(req.api_key).messages.create(
            model=MODEL,
            max_tokens=2048,
            system=(
                "You research whether a software product has known vulnerabilities using web search, "
                "as a last resort after structured vulnerability databases found nothing. Be "
                "conservative — only report a finding if a credible source clearly ties it to this "
                "product at approximately this version."
            ),
            messages=[{"role": "user", "content": user_content}],
            tools=[{"type": "web_search_20250305", "name": "web_search", "max_uses": 1}],
            output_config={"format": {"type": "json_schema", "schema": WEB_SEARCH_RESEARCH_SCHEMA}},
        )
    except Exception as e:
        _raise_for_anthropic_error(e)

    text = _final_text_block(response.content)
    if text is None:
        raise HTTPException(status_code=502, detail="Claude API returned no text content")

    data = json.loads(text)
    usage = UsageInfo(
        input_tokens=response.usage.input_tokens,
        output_tokens=response.usage.output_tokens,
        web_search_requests=_count_web_searches(response.usage, response.content),
    )
    result = WebSearchResearchResponse(**data, usage=usage)
    logger.info(
        "web_search_research product=%r version=%r ecosystem=%r package=%r -> findings=%d ids=%s usage=%s",
        req.product_name, req.version, req.ecosystem, req.package_name,
        len(result.findings), [f.identifier for f in result.findings], usage,
    )
    return result


# --- Bundled-package (formerly "Stage 3.5") detection ---------------------------

class BundledChangelogRequest(BaseModel):
    api_key: str
    product_name: str
    version: str
    vendor: str | None = None


class BundledChangelogResponse(BaseModel):
    found: bool
    changelog_text: str | None = None
    source_urls: list[str] = []
    usage: UsageInfo


BUNDLED_CHANGELOG_SCHEMA = {
    "type": "object",
    "properties": {
        "found": {"type": "boolean"},
        "changelog_text": {
            "type": ["string", "null"],
            "description": (
                "The relevant portion of this product's official changelog/release notes text for "
                "approximately this version, quoted or closely paraphrased from what you found via "
                "web search — especially any lines mentioning bundled/embedded third-party "
                "components (libraries, executables) and the versions they were updated to. Null "
                "if found=false."
            ),
        },
    },
    "required": ["found", "changelog_text"],
    "additionalProperties": False,
}


@app.post("/v1/bundled-components/discover-changelog", response_model=BundledChangelogResponse)
def bundled_discover_changelog(req: BundledChangelogRequest) -> BundledChangelogResponse:
    """Bundled-package detection, step 1: find this product's own official changelog/release-note
    text for approximately this version via web search (max_uses=1, same shape/budget as Stage4's
    web_search_research). Only returns raw/quoted text — never asked to judge vulnerabilities or
    name a CVE/GHSA id here; that judgment is deliberately deferred to structured OSV/NVD lookups
    downstream in the backend (see the plan's §3-1), not this call.
    """
    user_content = (
        f"Product: {req.product_name} (vendor: {req.vendor or 'unknown'}), version {req.version}\n\n"
        "Search the web for this product's own official changelog, release notes, or \"what's new\" "
        "page covering approximately this version. Return the relevant text verbatim or closely "
        "paraphrased — do not summarize away specific version numbers. Pay particular attention to "
        "any mention of bundled, embedded, or vendored third-party components (e.g. \"updated "
        "bundled 7-Zip to 26.02\", \"upgraded embedded OpenSSL to 3.2.1\") since that is what this "
        "text will be used to look for. If you cannot find an official changelog/release-note page "
        "for this product/version, set found=false. Respond only via the JSON schema."
    )

    try:
        response = _client(req.api_key).messages.create(
            model=MODEL,
            max_tokens=2048,
            system=(
                "You locate and quote a software product's own official changelog/release-note text "
                "for a given version, using web search. You never judge vulnerabilities or report a "
                "CVE/GHSA id — you only find and return the relevant text verbatim/paraphrased."
            ),
            messages=[{"role": "user", "content": user_content}],
            tools=[{"type": "web_search_20250305", "name": "web_search", "max_uses": 1}],
            output_config={"format": {"type": "json_schema", "schema": BUNDLED_CHANGELOG_SCHEMA}},
        )
    except Exception as e:
        _raise_for_anthropic_error(e)

    text = _final_text_block(response.content)
    if text is None:
        raise HTTPException(status_code=502, detail="Claude API returned no text content")

    data = json.loads(text)
    usage = UsageInfo(
        input_tokens=response.usage.input_tokens,
        output_tokens=response.usage.output_tokens,
        web_search_requests=_count_web_searches(response.usage, response.content),
    )
    result = BundledChangelogResponse(**data, source_urls=_extract_source_urls(response.content), usage=usage)
    logger.info(
        "bundled_discover_changelog product=%r version=%r -> found=%s text_len=%s urls=%d usage=%s",
        req.product_name, req.version, result.found,
        len(result.changelog_text) if result.changelog_text else None, len(result.source_urls), usage,
    )
    return result


class BundledExtractRequest(BaseModel):
    api_key: str
    product_name: str
    version: str
    changelog_text: str


class BundledComponent(BaseModel):
    component_name: str
    version: str
    confidence: str


class BundledExtractResponse(BaseModel):
    bundled_components: list[BundledComponent] = []
    usage: UsageInfo


BUNDLED_EXTRACT_SCHEMA = {
    "type": "object",
    "properties": {
        "bundled_components": {
            "type": "array",
            "description": (
                "Zero or more (component, version) pairs of bundled/embedded third-party "
                "components mentioned in the changelog text, updated to a specific version in "
                "approximately this release. Empty array if none are mentioned — do not force a "
                "match. At most 10 — pick the 10 most clearly stated if the text mentions more."
            ),
            # Backend REVISE item 2 (senior review 2026-08-26): kept in sync with
            # BundledComponentResearchService.MAX_COMPONENTS_PER_ITEM — a changelog listing dozens of
            # components would otherwise trigger that many uncached, rate-limited NVD/OSV calls for
            # one item. The backend also enforces this cap itself (defense in depth against a model
            # that doesn't honor it), but constraining it here keeps the common case from ever
            # generating the excess in the first place.
            "maxItems": 10,
            "items": {
                "type": "object",
                "properties": {
                    "component_name": {
                        "type": "string",
                        "description": "The bundled component's own name, e.g. '7-Zip', 'OpenSSL'.",
                    },
                    "version": {
                        "type": "string",
                        "description": (
                            "The exact version string the component was updated to. Never emit "
                            "non-version text here (e.g. 'latest', 'stable', a bare build/commit "
                            "number with no version meaning) — omit that component entirely instead."
                        ),
                    },
                    "confidence": {"type": "string", "enum": ["high", "low"]},
                },
                "required": ["component_name", "version", "confidence"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["bundled_components"],
    "additionalProperties": False,
}


@app.post("/v1/bundled-components/extract", response_model=BundledExtractResponse)
def bundled_extract_components(req: BundledExtractRequest) -> BundledExtractResponse:
    """Bundled-package detection, step 2: pure text-understanding extraction of (component,
    version) pairs from already-fetched changelog text — no web_search tool attached (cheaper than
    step 1, see the plan's §3-2/§4). This step must NEVER emit a CVE/GHSA id or any vulnerability
    judgment of its own: it only extracts plain (name, version) facts. Whether an extracted pair is
    actually vulnerable is adjudicated downstream in the backend via OSV/NVD lookups, never here.
    """
    user_content = (
        f"Product: {req.product_name}, version {req.version}\n\n"
        f"Changelog/release-note text:\n{req.changelog_text}\n\n"
        "Extract every bundled/embedded third-party component name and the exact version it was "
        "updated to in this text. Only plain facts — component_name and version — never a CVE/GHSA "
        "id, never a statement of whether something is vulnerable or was a security fix; that is "
        "not your job here. Skip anything that isn't a real version string (e.g. 'latest', "
        "'stable', a bare build/commit number). If nothing qualifies, return an empty array. "
        "Respond only via the JSON schema."
    )

    try:
        response = _client(req.api_key).messages.create(
            model=MODEL,
            max_tokens=1536,
            system=(
                "You extract structured (component_name, version) facts from software changelog "
                "text — nothing else. You NEVER output a CVE id, a GHSA id, a security-advisory "
                "identifier, or any judgment about whether something is a vulnerability or a "
                "security fix; that determination is made elsewhere, not by you. You never invent a "
                "component or version not actually present in the text, and you never emit a "
                "non-version placeholder (e.g. 'latest', 'stable', a bare build number) as a "
                "version."
            ),
            messages=[{"role": "user", "content": user_content}],
            output_config={"format": {"type": "json_schema", "schema": BUNDLED_EXTRACT_SCHEMA}},
        )
    except Exception as e:
        _raise_for_anthropic_error(e)

    text = _final_text_block(response.content)
    if text is None:
        raise HTTPException(status_code=502, detail="Claude API returned no text content")

    data = json.loads(text)
    usage = UsageInfo(input_tokens=response.usage.input_tokens, output_tokens=response.usage.output_tokens)
    result = BundledExtractResponse(**data, usage=usage)
    logger.info(
        "bundled_extract_components product=%r version=%r -> components=%d usage=%s",
        req.product_name, req.version, len(result.bundled_components), usage,
    )
    return result
