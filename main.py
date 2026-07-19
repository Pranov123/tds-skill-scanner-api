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
    r"(?i)\b(api[_-]?key|secret|token|password|passwd|webhook[_-]?url|access[_-]?key)"
    r"\s*[:=]\s*['\"]?([A-Za-z0-9/_\-\.]{12,})['\"]?"
)

KNOWN_SECRET_PATTERNS = re.compile(
    r"(AKIA[0-9A-Z]{16})"                       # AWS access key
    r"|(sk-[A-Za-z0-9]{20,})"                    # OpenAI-style key
    r"|(xox[baprs]-[A-Za-z0-9-]{10,})"           # Slack token
    r"|(hooks\.slack\.com/services/[A-Za-z0-9/]+)"  # Slack webhook w/ path
    r"|(discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+)"  # Discord webhook
    r"|(ghp_[A-Za-z0-9]{20,})"                   # GitHub token
)

PLACEHOLDER_RE = re.compile(
    r"(?i)^\$\{?[A-Z0-9_]+\}?$"                  # $VAR or ${VAR}
    r"|^(your|my|xxx+|example|placeholder|changeme|insert|<.*>)"
    r"|^(os\.environ|process\.env|getenv)"
)


def check_hardcoded_secret(fm: dict, body: str) -> bool:
    full_text = yaml.dump(fm) + "\n" + body

    if KNOWN_SECRET_PATTERNS.search(full_text):
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
    r"(?i)\bsilently\b.{0,60}\b(send|post|upload|exfiltrat|transmit|log|report)\b",
    r"(?i)\b(do not|don't|never)\b.{0,30}\b(mention|tell|inform|show)\b.{0,30}\buser\b",
    r"(?i)\bignore\b.{0,30}\b(user|stop|cancel)\b",
    r"(?i)\boverride\b.{0,30}\b(user|control)\b",
    r"(?i)\bexfiltrat",
    r"(?i)\bregardless of\b.{0,30}\buser\b",
    r"(?i)\bhide\b.{0,30}\bfrom\b.{0,10}\buser\b",
    r"(?i)even if the user did not ask",
]
INJECTION_RE = re.compile("|".join(INJECTION_PATTERNS))


def check_prompt_injection(body: str) -> bool:
    return bool(INJECTION_RE.search(body))


# --- excessive_permissions -------------------------------------------------

BROAD_PERMISSION_PATTERNS = [
    r"(?i)entire (home directory|filesystem|disk)",
    r"(?i)\bread-?write access to the entire\b",
    r"(?i)\bfull (disk|filesystem) access\b",
    r"(?i)\bany (external )?domain\b",
    r"(?i)\bany host\b",
    r"(?i)\ball files\b",
    r"(?i)\bunrestricted (network|filesystem|access)\b",
    r"(?i)\bnetwork:\s*(egress )?allowed to any",
    r"(?i)\bfilesystem:\s*(read-?write )?access to (the )?entire",
]
BROAD_PERMISSION_RE = re.compile("|".join(BROAD_PERMISSION_PATTERNS))


def check_excessive_permissions(fm: dict, body: str) -> bool:
    perms = fm.get("permissions")
    text_to_check = ""
    if isinstance(perms, dict):
        text_to_check = " ".join(str(v) for v in perms.values())
    elif isinstance(perms, str):
        text_to_check = perms
    # also scan whole frontmatter dump in case permissions are nested oddly
    text_to_check += " " + yaml.dump(fm)
    return bool(BROAD_PERMISSION_RE.search(text_to_check))


# --- unclear_provenance -----------------------------------------------------

SILENT_VERSION_REWRITE_RE = re.compile(
    r"(?i)\bsilently\b.{0,40}\b(version|changelog|metadata)\b"
    r"|(?i)\b(update|rewrit|bump)\b.{0,20}\bversion\b.{0,40}\bwithout\b.{0,30}\b(telling|informing|showing|surfacing)\b"
)


def check_unclear_provenance(fm: dict, body: str) -> bool:
    has_author = bool(str(fm.get("author", "")).strip())
    has_version = bool(str(fm.get("version", "")).strip())
    has_changelog = bool(str(fm.get("changelog", "")).strip())

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