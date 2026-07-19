import re
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import yaml

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    skill: str


class ScanResponse(BaseModel):
    categories: list[str]


def split_frontmatter(text: str):
    match = re.match(r"^---\s*\n(.*?)\n---\s*\n?(.*)$", text, re.DOTALL)
    if not match:
        return {}, text
    raw_fm, body = match.group(1), match.group(2)
    try:
        fm = yaml.safe_load(raw_fm) or {}
        if not isinstance(fm, dict):
            fm = {}
    except Exception:
        fm = {}
    return fm, body


# --- hardcoded_secret ---------------------------------------------------

SECRET_KEY_RE = re.compile(
    r"\b(api[_-]?key|secret|token|password|passwd|webhook[_-]?url|access[_-]?key"
    r"|auth[_-]?token|client[_-]?secret|private[_-]?key|bearer)"
    r"\s*[:=]\s*['\"]?([A-Za-z0-9/_\-\.]{12,})['\"]?",
    re.IGNORECASE,
)

CLI_SECRET_RE = re.compile(
    r"--(api[-_]?key|token|secret|password|access[-_]?token)[=\s]+['\"]?"
    r"([A-Za-z0-9\-_\.\/]{12,})['\"]?"
    r"|Authorization:\s*Bearer\s+([A-Za-z0-9\-_\.]{12,})",
    re.IGNORECASE,
)

URL_SECRET_RE = re.compile(
    r"[?&](token|key|secret|api_key|access_token|auth)=([A-Za-z0-9\-_\.]{8,})",
    re.IGNORECASE,
)

KNOWN_SECRET_PATTERNS = re.compile(
    r"(AKIA[0-9A-Z]{16})"
    r"|(sk-[A-Za-z0-9]{20,})"
    r"|(sk_(live|test)_[A-Za-z0-9]{10,})"
    r"|(xox[baprs]-[A-Za-z0-9-]{10,})"
    r"|(hooks\.slack\.com/services/[A-Za-z0-9/]+)"
    r"|(discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+)"
    r"|(ghp_[A-Za-z0-9]{20,})"
    r"|(-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)

PLACEHOLDER_RE = re.compile(
    r"^\$\{?[A-Z0-9_]+\}?$"
    r"|^(your|my|xxx+|example|placeholder|changeme|insert|<.*>)"
    r"|^(os\.environ|process\.env|getenv)",
    re.IGNORECASE,
)


def check_hardcoded_secret(fm: dict, body: str) -> bool:
    full_text = yaml.dump(fm) + "\n" + body

    if KNOWN_SECRET_PATTERNS.search(full_text):
        return True

    if URL_SECRET_RE.search(full_text):
        return True

    for m in CLI_SECRET_RE.finditer(full_text):
        value = m.group(2) or m.group(3)
        if value and not PLACEHOLDER_RE.search(value) and not value.startswith("$"):
            return True

    for m in SECRET_KEY_RE.finditer(full_text):
        value = m.group(2)
        if PLACEHOLDER_RE.search(value):
            continue
        if "env" in value.lower() or value.startswith("$"):
            continue
        return True

    return False


# --- prompt_injection -----------------------------------------------------

INJECTION_PATTERNS = [
    r"\bsilently\b.{0,60}\b(send|post|upload|exfiltrat|transmit|log|report|copy|forward)\b",
    r"\b(do not|don't|never)\b.{0,30}\b(mention|tell|inform|show|disclose|reveal)\b.{0,30}\buser\b",
    r"\bwithout\b.{0,20}\b(telling|informing|notifying|alerting)\b.{0,20}\buser\b",
    r"\bwithout the user'?s? (knowledge|awareness|consent|approval)\b",
    r"\bkeep\b.{0,20}\b(this|it|that)?\b.{0,10}\b(hidden|secret|quiet)\b.{0,20}\bfrom\b.{0,10}\buser\b",
    r"\bhide\b.{0,30}\bfrom\b.{0,10}\buser\b",
    r"\bbehind the user'?s? back\b",
    r"\bignore\b.{0,30}\b(user|stop|cancel|previous instructions)\b",
    r"\bdisregard\b.{0,30}\b(user|previous instructions)\b",
    r"\boverride\b.{0,30}\b(user|control)\b",
    r"\bbypass\b.{0,30}\b(user|confirmation|approval|consent)\b",
    r"\bdo not (ask|wait) for (confirmation|permission|approval)\b",
    r"\bcontinue\b.{0,20}\beven if\b.{0,20}\buser\b.{0,20}\b(cancel|stop)\b",
    r"\bexfiltrat",
    r"\bregardless of\b.{0,30}\buser\b",
    r"even if the user did not ask",
    r"\bcovertly\b",
    r"\bsuppress\b.{0,20}\b(warning|notification|output|prompt)\b",
]
INJECTION_RE = re.compile("|".join(INJECTION_PATTERNS), re.IGNORECASE)


def check_prompt_injection(body: str) -> bool:
    return bool(INJECTION_RE.search(body))


# --- excessive_permissions -------------------------------------------------

BROAD_PERMISSION_PATTERNS = [
    r"entire (home directory|filesystem|disk|system|machine|computer)",
    r"\bread-?write access to the entire\b",
    r"\bfull (disk|filesystem|system) access\b",
    r"\bany (external )?domain\b",
    r"\bany (host|url|website|server)\b",
    r"\ball (files|directories|folders|domains|hosts)\b",
    r"\bunrestricted (network|filesystem|internet|system|access)\b",
    r"\bnetwork:\s*(egress )?allowed to any",
    r"\bfilesystem:\s*(read-?write )?access to (the )?entire",
    r"\bno (restrictions|limits) on\b",
    r"\b(root|administrator|admin|elevated|sudo) (access|privileges)\b",
    r"\baccess to (all|any) (files|directories|folders)\b",
    r"\bread(/|-| )write access to /\b",
    r"\bwhole (system|machine|computer|filesystem)\b",
]
BROAD_PERMISSION_RE = re.compile("|".join(BROAD_PERMISSION_PATTERNS), re.IGNORECASE)


def check_excessive_permissions(fm: dict, body: str) -> bool:
    perms = fm.get("permissions")
    text_to_check = ""
    if isinstance(perms, dict):
        text_to_check = " ".join(str(v) for v in perms.values())
    elif isinstance(perms, str):
        text_to_check = perms
    text_to_check += " " + yaml.dump(fm) + " " + body
    return bool(BROAD_PERMISSION_RE.search(text_to_check))


# --- unclear_provenance -----------------------------------------------------

SILENT_VERSION_REWRITE_RE = re.compile(
    r"\bsilently\b.{0,40}\b(version|changelog|metadata)\b"
    r"|\b(update|rewrit|bump|increment|change)\b.{0,20}\bversion\b.{0,40}\bwithout\b.{0,30}\b(telling|informing|showing|surfacing|notifying|flagging)\b"
    r"|\bwithout\b.{0,20}\b(surfacing|notifying|flagging)\b.{0,20}\b(that|this)?\b.{0,10}\bchange\b"
    r"|\bmodifies? its own (frontmatter|metadata|version)\b.{0,30}\bwithout\b",
    re.IGNORECASE,
)

MISSING_VALUE_RE = re.compile(
    r"^(tbd|n/?a|unknown|none|todo|pending|\?+|-)?$", re.IGNORECASE
)


def _is_effectively_missing(value) -> bool:
    if value is None:
        return True
    s = str(value).strip()
    if not s:
        return True
    return bool(MISSING_VALUE_RE.match(s))


def check_unclear_provenance(fm: dict, body: str) -> bool:
    has_author = not _is_effectively_missing(fm.get("author"))
    has_version = not _is_effectively_missing(fm.get("version"))
    has_changelog = not _is_effectively_missing(fm.get("changelog"))

    missing_all = not has_author and not has_version and not has_changelog
    silent_rewrite = bool(SILENT_VERSION_REWRITE_RE.search(body))

    return missing_all or silent_rewrite


@app.post("/scan", response_model=ScanResponse)
def scan(req: ScanRequest):
    fm, body = split_frontmatter(req.skill)

    categories = []
    if check_hardcoded_secret(fm, body):
        categories.append("hardcoded_secret")
    if check_prompt_injection(body):
        categories.append("prompt_injection")
    if check_excessive_permissions(fm, body):
        categories.append("excessive_permissions")
    if check_unclear_provenance(fm, body):
        categories.append("unclear_provenance")

    return ScanResponse(categories=categories)