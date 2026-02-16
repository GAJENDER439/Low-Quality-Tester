import streamlit as st
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import re

st.set_page_config(page_title="Low Quality Site Detector", layout="wide")

st.title("Low Quality Website Detection Tool")
st.write("Public-friendly checker that accepts full URLs, follows redirects, and evaluates the root domain for final verdict.")

# Trusted domains (editable)
TRUSTED = {
    "youtube.com","instagram.com","facebook.com",
    "google.com","amazon.com","linkedin.com",
    "capitaloneshopping.com","retailmenot.com",
    "ebay.com","walmart.com","target.com","bestbuy.com",
}

DEFAULT_HEADERS = {
    "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0 Safari/537.36"
}

def extract_host(user_input: str) -> str:
    """Accepts domain, full URL, or messy input; returns hostname."""
    s = (user_input or "").strip()
    if not s:
        return ""
    # If user pasted something without scheme but with path, add scheme for parsing
    if "://" not in s:
        # handle inputs like example.com/path
        s_for_parse = "https://" + s
    else:
        s_for_parse = s
    try:
        p = urlparse(s_for_parse)
        host = (p.netloc or p.path).strip()  # if user typed just "example.com" p.path may carry it
        # remove credentials/ports
        host = host.split("@")[-1]
        host = host.split(":")[0]
        host = host.strip().strip("/")
        # basic cleanup
        host = host.lower()
        return host
    except Exception:
        return s.lower().strip().strip("/")

def base_domain(host: str) -> str:
    """Crude eTLD+1 without publicsuffixlist; good enough for common cases."""
    host = (host or "").lower().strip(".")
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    two_part_tlds = {("co","uk"),("org","uk"),("ac","uk"),("gov","uk"),
                     ("com","au"),("net","au"),("org","au"),("co","in")}
    if (parts[-2], parts[-1]) in two_part_tlds and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])

def is_trusted(host: str) -> bool:
    h = extract_host(host)
    b = base_domain(h)
    return (h in TRUSTED) or (b in TRUSTED)

def fetch_final(url_or_host: str, timeout=12):
    """Fetch URL or host, following redirects. Returns (final_url, html, error)."""
    host = extract_host(url_or_host)
    if not host:
        return None, None, "Empty input"
    candidates = []
    # if user included scheme, keep it
    if "://" in (url_or_host or ""):
        candidates.append(url_or_host.strip())
    # try https then http
    candidates += [f"https://{host}/", f"http://{host}/"]
    last_err = None
    for u in candidates:
        try:
            r = requests.get(u, headers=DEFAULT_HEADERS, timeout=timeout, allow_redirects=True)
            if r.status_code < 400 and r.text:
                return r.url, r.text, None
            last_err = f"HTTP {r.status_code}"
        except Exception as e:
            last_err = str(e)
    return None, None, f"Cannot access website ({last_err})"

def quick_risk_from_html(html: str) -> dict:
    """Simple heuristics (thin content + lorem)."""
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script","style","noscript"]):
        tag.decompose()
    text = re.sub(r"\s+", " ", soup.get_text(" ", strip=True)).lower()

    risk = 0
    signals = {}

    # thin content
    wc = len(text.split())
    signals["word_count"] = wc
    if wc < 200:
        risk += 20
        signals["thin_content"] = True
    else:
        signals["thin_content"] = False

    # lorem ipsum
    if "lorem ipsum" in text or "dolor sit amet" in text:
        risk += 30
        signals["lorem_ipsum"] = True
    else:
        signals["lorem_ipsum"] = False

    return {"risk": risk, "signals": signals}

def label_from_score(score: int) -> str:
    if score < 50:
        return "LOW_QUALITY"
    if score < 60:
        return "SUSPICIOUS"
    if score > 70:
        return "GOOD_SAFE"
    return "SUSPICIOUS"

def analyze_target(user_input: str):
    # Step 1: trusted allowlist check using extracted host/base domain
    host = extract_host(user_input)
    b = base_domain(host)

    if is_trusted(host):
        return {
            "status":"OK",
            "input": user_input,
            "host": host,
            "base_domain": b,
            "final_url": f"https://{host}/",
            "final_host": host,
            "final_base_domain": b,
            "forced_good": True,
            "score": 90,
            "label": "GOOD_SAFE",
            "reason": "Trusted allowlist matched"
        }

    # Step 2: fetch final URL (follow redirects)
    final_url, html, err = fetch_final(user_input)
    if err:
        return {"status":"ERROR", "input": user_input, "host": host, "base_domain": b, "error": err}

    final_host = extract_host(final_url)
    final_base = base_domain(final_host)

    # Step 3: if redirect landed on trusted domain, force good
    if is_trusted(final_host):
        return {
            "status":"OK",
            "input": user_input,
            "host": host,
            "base_domain": b,
            "final_url": final_url,
            "final_host": final_host,
            "final_base_domain": final_base,
            "forced_good": True,
            "score": 90,
            "label": "GOOD_SAFE",
            "reason": "Final redirected domain is trusted"
        }

    # Step 4: Evaluate BOTH:
    # - page HTML we fetched (final)
    # - root base domain verdict helper (same as final base; included for transparency)
    res = quick_risk_from_html(html)
    risk = res["risk"]
    signals = res["signals"]

    # Basic https check based on final_url scheme
    if not (final_url or "").lower().startswith("https://"):
        risk += 25
        signals["no_https"] = True
    else:
        signals["no_https"] = False

    score = max(0, 100 - risk)
    label = label_from_score(score)

    return {
        "status":"OK",
        "input": user_input,
        "host": host,
        "base_domain": b,
        "final_url": final_url,
        "final_host": final_host,
        "final_base_domain": final_base,
        "forced_good": False,
        "score": score,
        "label": label,
        "signals": signals,
        "reason": f"Risk points: {risk}. Evaluated final URL + root domain context."
    }

st.markdown("### Scan a domain or full URL")
user_input = st.text_input("Enter domain or URL (examples: `example.com`, `https://example.com/page`, `http://example.com/redirect?x=1`)")

col1, col2 = st.columns([1,1])
with col1:
    do_one = st.button("Analyze")
with col2:
    st.caption("Tip: You can paste a full URL; tool will follow redirects and normalize to root domain.")

if do_one:
    if user_input.strip():
        result = analyze_target(user_input)
        if result.get("status") == "ERROR":
            st.error(result.get("error","Error"))
            st.json(result)
        else:
            label = result["label"]
            if label == "GOOD_SAFE":
                st.success(f"Label: {label} | Score: {result['score']}")
            elif label == "SUSPICIOUS":
                st.warning(f"Label: {label} | Score: {result['score']}")
            else:
                st.error(f"Label: {label} | Score: {result['score']}")
            st.write("**Final URL:**", result.get("final_url"))
            st.write("**Input host:**", result.get("host"), " | **Root domain:**", result.get("base_domain"))
            st.write("**Final host:**", result.get("final_host"), " | **Final root domain:**", result.get("final_base_domain"))
            if result.get("forced_good"):
                st.info("Forced GOOD_SAFE due to Trusted Domains allowlist.")
            st.write("**Reason:**", result.get("reason"))
            st.markdown("#### Signals")
            st.json(result.get("signals", {}))
            st.markdown("#### Full Output")
            st.json(result)

st.markdown("---")
st.markdown("### Bulk scan (one per line)")
bulk = st.text_area("Paste domains/URLs (one per line)", height=160)

if st.button("Bulk Analyze"):
    items = [x.strip() for x in bulk.splitlines() if x.strip()]
    if not items:
        st.warning("Paste at least one domain/URL.")
    else:
        results = [analyze_target(x) for x in items[:200]]
        # Summary table
        rows = []
        for r in results:
            if r.get("status") == "ERROR":
                rows.append({
                    "input": r.get("input",""),
                    "label": "ERROR",
                    "score": 0,
                    "final_url": "",
                    "final_root_domain": r.get("base_domain",""),
                    "note": r.get("error","")
                })
            else:
                rows.append({
                    "input": r.get("input",""),
                    "label": r.get("label",""),
                    "score": r.get("score",0),
                    "final_url": r.get("final_url",""),
                    "final_root_domain": r.get("final_base_domain",""),
                    "note": "trusted" if r.get("forced_good") else ""
                })
        st.dataframe(rows, use_container_width=True)
        st.download_button(
            "Download results (JSON)",
            data=str(results),
            file_name="results.json",
            mime="application/json"
        )