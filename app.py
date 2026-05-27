from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import sqlite3
import os
os.environ["PYTHONUNBUFFERED"] = "1"
import sys
import datetime
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ml"))
from feature_extractor import scan_url
app = Flask(__name__, static_folder="Frontend", static_url_path="")
CORS(app, resources={
    r"/api/*": {
        "origins": [
            r"^chrome-extension://.*$",
            r"^http://localhost(:\d+)?$",
            r"^http://127\.0\.0\.1(:\d+)?$"
        ]
    }
})
DB_FILE = os.path.join(os.path.dirname(__file__), "scan_logs.db")

import time
from threading import Lock
from urllib.parse import urlparse

class ScanCache:
    def __init__(self, ttl_seconds=600, max_size=1000):
        self.cache = {}
        self.ttl = ttl_seconds
        self.max_size = max_size
        self.lock = Lock()
        self.hits = 0
        self.misses = 0

    def get(self, url):
        with self.lock:
            entry = self.cache.get(url)
            if not entry:
                self.misses += 1
                return None
            result, timestamp = entry
            if time.time() - timestamp > self.ttl:
                del self.cache[url]  # Expired
                self.misses += 1
                return None
            self.hits += 1
            return result

    def set(self, url, result):
        with self.lock:
            if len(self.cache) >= self.max_size:
                oldest_key = next(iter(self.cache))
                del self.cache[oldest_key]
            self.cache[url] = (result, time.time())

    def clear(self):
        with self.lock:
            self.cache.clear()
            self.hits = 0
            self.misses = 0

cache = ScanCache()

TRUSTED_DOMAINS = {
    # High-Traffic Giants
    "google.com", "youtube.com", "facebook.com", "amazon.com", "wikipedia.org", 
    "twitter.com", "instagram.com", "linkedin.com", "microsoft.com", "apple.com", 
    "netflix.com", "github.com", "reddit.com", "yahoo.com", "bing.com",
    # Payment Gateways & FinTech
    "stripe.com", "paypal.com", "paypalobjects.com", "razorpay.com", "paytm.com", 
    "billdesk.com", "adyen.com", "visa.com", "mastercard.com", "americanexpress.com",
    "discover.com", "bankofamerica.com", "chase.com", "wellsfargo.com", "hsbc.com"
}

def is_trusted_domain(url):
    try:
        hostname = urlparse(url).netloc.lower()
        if hostname.startswith("www."):
            hostname = hostname[4:]
        hostname = hostname.split(":")[0]  # Remove port
        for domain in TRUSTED_DOMAINS:
            if hostname == domain or hostname.endswith("." + domain):
                return True
    except:
        pass
    return False

def make_trusted_response(url):
    return {
        "url": url,
        "original_url": url,
        "is_phishing": False,
        "label": "LEGITIMATE",
        "confidence": 100.0,
        "risk_score": 0.0,
        "features": {
            "has_ip": False,
            "url_length": -1,
            "uses_shortener": False,
            "has_at_symbol": False,
            "uses_https": True,
            "domain_age_suspicious": False,
            "has_prefix_suffix": False
        }
    }

import socket
from ipaddress import ip_address

def is_local_or_private_ip(url):
    try:
        parsed = urlparse(url)
        hostname = parsed.netloc.split(":")[0]
        
        # 1. Block loopback representations immediately
        if hostname.lower() in ("localhost", "127.0.0.1", "[::1]", "0.0.0.0"):
            return True
            
        # 2. Resolve the hostname to an IP address
        ip_string = socket.gethostbyname(hostname)
        ip_obj = ip_address(ip_string)
        
        # 3. Check against loopback, private, or link-local network ranges
        if ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local:
            return True
            
        return False
    except Exception as e:
        # If DNS fails or errors, it is safer to reject or fall back,
        # but standard local/private checks shouldn't fail silently.
        return False

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS scan_logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            url         TEXT    NOT NULL,
            label       TEXT    NOT NULL,
            risk_score  REAL    NOT NULL,
            confidence  REAL    NOT NULL,
            scanned_at  TEXT    NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def log_scan(url, label, risk_score, confidence):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute(
        "INSERT INTO scan_logs (url, label, risk_score, confidence, scanned_at) VALUES (?,?,?,?,?)",
        (url, label, risk_score, confidence, datetime.datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()

@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")

@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({"error": "Missing 'url' in request body"}), 400
    url = data["url"].strip()
    if not url:
        return jsonify({"error": "URL cannot be empty"}), 400
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    if is_local_or_private_ip(url):
        return jsonify({"error": "Scanning of local or private network addresses is prohibited for security reasons."}), 400
    try:
        # 1. Whitelist Bypass Check
        if is_trusted_domain(url):
            print(f"    [WHITELIST] Instant safe bypass triggered for {url}")
            result = make_trusted_response(url)
            log_scan(
                url=result["url"],
                label=result["label"],
                risk_score=result["risk_score"],
                confidence=result["confidence"],
            )
            return jsonify(result), 200

        # 2. Temporary Cache Check
        cached_result = cache.get(url)
        if cached_result:
            print(f"    [CACHE HIT] Instant cached result returned for {url}")
            log_scan(
                url=cached_result["url"],
                label=cached_result["label"],
                risk_score=cached_result["risk_score"],
                confidence=cached_result["confidence"],
            )
            return jsonify(cached_result), 200

        # 3. Live Scan
        fetch_html = data.get("fetch_html", True)
        skip_whois = data.get("skip_whois", False)
        result = scan_url(url, fetch_html=fetch_html, skip_whois=skip_whois)
        if "error" in result:
            return jsonify(result), 500

        # Cache the clean result for future lookups
        cache.set(url, result)
        print(f"    [CACHE STORE] Saved scan result for {url}")

        log_scan(
            url=result["url"],
            label=result["label"],
            risk_score=result["risk_score"],
            confidence=result["confidence"],
        )
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/history", methods=["GET"])
def api_history():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM scan_logs ORDER BY id DESC LIMIT 50")
    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify(rows), 200

@app.route("/api/history", methods=["DELETE"])
def api_clear_history():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM scan_logs")
    conn.commit()
    conn.close()
    return jsonify({"status": "success", "message": "History cleared"}), 200

@app.route("/api/stats", methods=["GET"])
def api_stats():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM scan_logs")
    total = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM scan_logs WHERE label='PHISHING'")
    phishing = c.fetchone()[0]
    conn.close()
    return jsonify({
        "total_scans": total,
        "phishing_detected": phishing,
        "legitimate": total - phishing,
        "phishing_rate": round(phishing / total * 100, 1) if total > 0 else 0,
        "cache_hits": cache.hits,
        "cache_misses": cache.misses,
        "cache_size": len(cache.cache)
    }), 200

if __name__ == "__main__":
    init_db()
    print("\n  PhishGuard API  –  http://localhost:5000")
    print("  POST /api/scan    →  scan a URL")
    print("  GET  /api/history →  scan history")
    print("  GET  /api/stats   →  aggregate stats\n")
    app.run(debug=True, host="0.0.0.0", port=5000)
