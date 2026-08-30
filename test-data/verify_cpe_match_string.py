#!/usr/bin/env python3
"""Follow-up NVD CPE dictionary verification: for a set of exact cpe23Uri strings (mix of
this task's own golden-300.csv ground truth AND job 168's actual returned CPE strings),
confirms via cpeMatchString whether each literal string is a genuine NVD CPE dictionary
entry (rules out the app having fabricated/hallucinated a CPE) -- does NOT decide which one
is "more correct" for a given version; that judgment is made by a human reading the output.
"""
import json
import time
import urllib.request
import urllib.parse

UA = "vulncheck-research-golden300-dataset-builder/1.0 (+internal research tool, non-commercial)"
SLEEP_S = 6.5


def match(cpe_match_string):
    url = "https://services.nvd.nist.gov/rest/json/cpes/2.0?cpeMatchString=" + urllib.parse.quote(cpe_match_string) + "&resultsPerPage=20"
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode("utf-8")), url


# (label, cpeMatchString prefix -- no trailing version, to see the whole version range)
CANDIDATES = [
    ("Docker Desktop -- mine", "cpe:2.3:a:docker:desktop"),
    ("Docker Desktop -- app's", "cpe:2.3:a:docker:docker_desktop"),
    ("Postman -- mine", "cpe:2.3:a:getpostman:postman"),
    ("Postman -- app's", "cpe:2.3:a:postman:postman"),
    ("Audacity -- mine", "cpe:2.3:a:audacityteam:audacity"),
    ("Audacity -- app's", "cpe:2.3:a:audacity:audacity"),
    ("Adobe Acrobat Reader DC -- mine", "cpe:2.3:a:adobe:acrobat_reader_dc"),
    ("Adobe Acrobat Reader DC -- app's", "cpe:2.3:a:adobe:acrobat_reader"),
    ("Symantec Endpoint Protection -- mine", "cpe:2.3:a:symantec:endpoint_protection"),
    ("Symantec Endpoint Protection -- app's", "cpe:2.3:a:broadcom:symantec_endpoint_protection"),
    ("Node.js -- mine", "cpe:2.3:a:nodejs:node.js"),
    ("Node.js -- app's", "cpe:2.3:a:joyent:node.js"),
    ("RabbitMQ -- mine", "cpe:2.3:a:pivotal_software:rabbitmq"),
    ("RabbitMQ -- app's", "cpe:2.3:a:anynines:rabbitmq"),
    ("Kibana -- mine", "cpe:2.3:a:elasticsearch:kibana"),
    ("Kibana -- app's", "cpe:2.3:a:elastic:kibana"),
    ("Tableau Desktop -- mine", "cpe:2.3:a:tableau:tableau_desktop"),
    ("Tableau Desktop -- app's", "cpe:2.3:a:schneider_electric:tableau_desktop"),
    ("PDF-XChange Editor -- mine", "cpe:2.3:a:tracker-software:pdf-xchange_editor"),
    ("PDF-XChange Editor -- app's", "cpe:2.3:a:pdf-xchange:pdf-xchange_editor"),
    ("Greenshot -- mine", "cpe:2.3:a:getgreenshot:greenshot"),
    ("Greenshot -- app's", "cpe:2.3:a:greenshot:greenshot"),
    ("Ditto -- app's (unrelated real product?)", "cpe:2.3:a:eclipse:ditto"),
]

for label, prefix in CANDIDATES:
    try:
        data, url = match(prefix)
        total = data.get("totalResults", 0)
        versions = []
        for p in data.get("products", [])[:20]:
            name = p.get("cpe", {}).get("cpeName", "")
            parts = name.split(":")
            if len(parts) > 5:
                versions.append(parts[5])
        print(f"=== {label} ({prefix}) === total={total} sample_versions={versions}")
    except Exception as e:
        print(f"=== {label} ({prefix}) === ERROR {type(e).__name__}: {e}")
    time.sleep(SLEEP_S)
