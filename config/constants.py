"""Shared constants: risk thresholds, evidence weights, tool limits."""

APP_NAME = "ScamSathi BD"
TAGLINE = "Don't Trust. Verify First."
APP_VERSION = "1.0.0"

MAX_INPUT_LENGTH = 5000
MAX_URLS_PER_INVESTIGATION = 3
MAX_TOOL_CALLS = 6
MAX_AGENT_TURNS = 8

# Risk categories (inclusive lower bound, exclusive upper bound)
RISK_LEVELS = [
    (0, 20, "Low"),
    (20, 40, "Guarded"),
    (40, 70, "Suspicious"),
    (70, 101, "High"),
]

# Maximum contribution per evidence group (total 100)
WEIGHTS = {
    "safe_browsing": 40,
    "virustotal": 25,
    "urlhaus": 20,
    "domain": 10,
    "message": 5,
}

# Evidence statuses
STATUS_COMPLETED = "completed"       # check ran and returned a result (match or no match)
STATUS_NOT_FOUND = "not_found"       # check ran, nothing matched
STATUS_UNAVAILABLE = "unavailable"   # provider error / rate limit / timeout
STATUS_FAILED = "failed"             # unexpected local failure
STATUS_NOT_CONFIGURED = "not_configured"
STATUS_SKIPPED = "skipped"           # agent chose not to run / limits reached

SEVERITY_NONE = "none"
SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"

INVESTIGATION_COMPLETE = "Complete"
INVESTIGATION_PARTIAL = "Partial"
INVESTIGATION_FAILED = "Failed"

SUPPORTED_LANGUAGES = {"en": "English", "bn": "বাংলা"}

# Brands frequently impersonated in Bangladesh-targeted scams.
BD_BRAND_KEYWORDS = [
    "bkash", "nagad", "rocket", "upay", "dbbl", "brac", "citybank", "ucb",
    "sonali", "janata", "grameenphone", "robi", "banglalink", "teletalk",
    "daraz", "pathao", "foodpanda", "bangladesh bank", "nid", "ec.gov",
    "facebook", "whatsapp", "google", "microsoft", "paypal", "amazon",
]

OFFICIAL_DOMAINS = {
    "bkash.com", "nagad.com.bd", "dutchbanglabank.com", "bracbank.com",
    "thecitybank.com", "sonalibank.com.bd", "grameenphone.com", "robi.com.bd",
    "banglalink.net", "teletalk.com.bd", "daraz.com.bd", "pathao.com",
    "foodpanda.com.bd", "bb.org.bd", "nidw.gov.bd", "facebook.com",
    "whatsapp.com", "google.com", "microsoft.com", "paypal.com", "amazon.com",
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "click", "link",
    "work", "live", "icu", "cam", "rest", "zip", "mov", "info", "cfd", "sbs",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly", "rb.gy", "is.gd",
    "shorturl.at", "tiny.cc", "s.id", "rebrand.ly", "ow.ly", "t.ly",
}
