"""CVE lookup against the public NVD API (API 2.0).

No credentials are needed: without an API key the NVD allows 5
requests per 30 seconds, so this module throttles itself to one
request every 6 seconds (0.6 seconds with a key, from the NVD_API_KEY
environment variable or the --api-key flag). Results are cached on
disk for 7 days, so repeat scans of the same components make no
network calls at all.

Every CVE finding records its match basis: the component, the
version, the exact evidence string that produced the fingerprint,
and the CPE name that was queried. A CVE is only ever reported for a
component with a concrete version — never for a versionless
fingerprint, where the query would return every CVE ever filed
against the product.
"""
import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_TTL_SECONDS = 7 * 24 * 3600
NO_KEY_INTERVAL = 6.0        # 5 requests / 30 s without a key
KEY_INTERVAL = 0.6           # 50 requests / 30 s with a key
RESULTS_PER_PAGE = 2000      # NVD maximum; one page per component


class Throttle:
    """Enforces the NVD rate limit between requests."""

    def __init__(self, interval):
        self.interval = interval
        self._next_at = 0.0

    def wait(self):
        now = time.monotonic()
        if now < self._next_at:
            time.sleep(self._next_at - now)
        self._next_at = time.monotonic() + self.interval


def default_cache_dir():
    return os.path.join(os.path.expanduser("~"), ".cache", "firmwarescope", "nvd")


def _cache_path(cache_dir, cpe):
    digest = hashlib.sha256(cpe.encode("utf-8")).hexdigest()[:16]
    return os.path.join(cache_dir, digest + ".json")


def _cache_read(cache_dir, cpe):
    try:
        with open(_cache_path(cache_dir, cpe), "r", encoding="utf-8") as f:
            entry = json.load(f)
    except (OSError, ValueError):
        return None
    if entry.get("cpe") != cpe:
        return None
    if time.time() - entry.get("fetched_at", 0) > CACHE_TTL_SECONDS:
        return None
    return entry.get("cves")


def _cache_write(cache_dir, cpe, cves):
    try:
        os.makedirs(cache_dir, exist_ok=True)
        with open(_cache_path(cache_dir, cpe), "w", encoding="utf-8") as f:
            json.dump({"cpe": cpe, "fetched_at": time.time(), "cves": cves}, f)
    except OSError:
        pass                                     # cache failure is not fatal


def _best_cvss(cve):
    """Pick the strongest CVSS score NVD reports for a CVE (v3.1 > v3.0 > v2)."""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            data = entries[0]["cvssData"]
            return {
                "version": data.get("version"),
                "score": data.get("baseScore"),
                "severity": data.get("baseSeverity"),
                "vector": data.get("vectorString"),
            }
    return {"version": None, "score": None, "severity": None, "vector": None}


def severity_for_score(score):
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def parse_nvd_response(payload):
    """Reduce a raw NVD API 2.0 response to our CVE records."""
    out = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        descriptions = [d.get("value", "") for d in cve.get("descriptions", [])
                        if d.get("lang") == "en"]
        cvss = _best_cvss(cve)
        out.append({
            "id": cve.get("id"),
            "description": descriptions[0] if descriptions else "",
            "published": cve.get("published"),
            "modified": cve.get("lastModified"),
            "cvss": cvss,
            "severity": (cvss["severity"] or severity_for_score(cvss["score"])).lower(),
            "references": [r.get("url") for r in cve.get("references", [])][:5],
            "url": "https://nvd.nist.gov/vuln/detail/%s" % cve.get("id"),
        })
    # Highest score first; unscored last.
    out.sort(key=lambda c: (c["cvss"]["score"] is None,
                            -(c["cvss"]["score"] or 0)))
    return out


def query_cpe(cpe, cache_dir=None, api_key=None, throttle=None):
    """Look up CVEs for one CPE name.

    Returns {"cpe", "cves", "from_cache", "error"}. On any failure the
    error field is set and cves is empty — a lookup failure never
    aborts a scan.
    """
    cache_dir = cache_dir or default_cache_dir()
    cached = _cache_read(cache_dir, cpe)
    if cached is not None:
        return {"cpe": cpe, "cves": cached, "from_cache": True, "error": None}

    if throttle is None:
        throttle = Throttle(KEY_INTERVAL if api_key else NO_KEY_INTERVAL)
    throttle.wait()

    query = urllib.parse.urlencode({
        "cpeName": cpe,
        "resultsPerPage": RESULTS_PER_PAGE,
    })
    request = urllib.request.Request(NVD_BASE + "?" + query)
    request.add_header("User-Agent", "firmwarescope/1.0.0")
    if api_key:
        request.add_header("apiKey", api_key)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code in (403, 429):
            detail = ("NVD rate limit reached (HTTP %d). Wait a minute and "
                      "re-run, or set NVD_API_KEY for a higher limit."
                      % exc.code)
        else:
            detail = "NVD request failed: HTTP %d" % exc.code
        return {"cpe": cpe, "cves": [], "from_cache": False, "error": detail}
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        return {"cpe": cpe, "cves": [], "from_cache": False,
                "error": "NVD request failed: %s" % exc}

    cves = parse_nvd_response(payload)
    _cache_write(cache_dir, cpe, cves)
    return {"cpe": cpe, "cves": cves, "from_cache": False, "error": None}


def lookup(components, cache_dir=None, api_key=None):
    """Look up CVEs for every versioned component fingerprint.

    Returns {"findings": [...], "queried": n, "errors": [...]}.
    Each finding is one CVE on one component, with the full match
    basis: component, version, evidence string, evidence source, and
    the CPE name that was queried.
    """
    throttle = Throttle(KEY_INTERVAL if api_key else NO_KEY_INTERVAL)
    findings = []
    errors = []
    queried = 0
    for component in components:
        cpe = component.get("cpe")
        if not cpe:
            continue
        queried += 1
        result = query_cpe(cpe, cache_dir=cache_dir, api_key=api_key,
                           throttle=throttle)
        if result["error"]:
            errors.append({"component": component["name"],
                           "version": component.get("version"),
                           "cpe": cpe, "error": result["error"]})
            continue
        for cve in result["cves"]:
            finding = dict(cve)
            finding["component"] = component["name"]
            finding["component_version"] = component.get("version")
            finding["match_basis"] = {
                "cpe": cpe,
                "evidence": component.get("evidence"),
                "evidence_source": component.get("evidence_source"),
                "offset": component.get("offset"),
            }
            findings.append(finding)
    return {"findings": findings, "queried": queried, "errors": errors}
