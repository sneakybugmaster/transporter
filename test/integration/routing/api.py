"""Tiny admin API client for run.sh: api.py METHOD PATH [JSON]."""
import http.cookiejar
import json
import os
import sys
import urllib.request

BASE = os.environ.get("API", "http://127.0.0.1:18081/api/v1")
JAR = os.environ.get("COOKIES", "/tmp/transporter-routing-cookies")

jar = http.cookiejar.MozillaCookieJar(JAR)
if os.path.exists(JAR) and os.path.getsize(JAR) > 0:
    jar.load(ignore_discard=True)
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

method, path = sys.argv[1], sys.argv[2]
data = sys.argv[3].encode() if len(sys.argv) > 3 else None
req = urllib.request.Request(BASE + path, data=data, method=method)
if data is not None:
    req.add_header("Content-Type", "application/json")
try:
    with opener.open(req) as resp:
        body = resp.read().decode()
except urllib.error.HTTPError as e:
    sys.stderr.write(f"{method} {path}: HTTP {e.code}: {e.read().decode()}\n")
    sys.exit(1)
jar.save(ignore_discard=True)
print(body)
