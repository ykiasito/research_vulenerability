#!/usr/bin/env python3
"""Senior-reviewer review item 5: strong-verification (cpeMatchString) pass over the 53
IDENTIFIED_CPE rows where golden-300.csv's ground truth and job 168's actual output already
AGREED on vendor:product. Until now, verify_cpe_match_string.py had only ever been run on the
14 rows where the two DISAGREED -- these 53 agreeing rows never received the same rigor and
were taken on faith. This confirms each vendor:product pair here is a genuine NVD CPE
dictionary entry (not a hallucinated/fabricated one on either side of the agreement) --
same purpose and same tool contract as verify_cpe_match_string.py, just applied to the
complementary set of rows. Sleeps 6.5s between requests (public NVD rate limit).

Persisted evidence (2026-08-29, senior-reviewer re-review item 5): unlike
golden300_registry_results.tsv / golden300_cpe_results.tsv, this script previously only
printed to stdout, leaving no on-disk record of the 53-row check once the terminal scrollback
was gone. Now appends every result to test-data/golden300_cpe_matchstring_results.tsv (same
append-only convention as the other two verification tsv files)."""
import json
import time
import urllib.request
import urllib.parse

UA = "vulncheck-research-golden300-dataset-builder/1.0 (+internal research tool, non-commercial)"
SLEEP_S = 6.5


def match(cpe_match_string):
    url = "https://services.nvd.nist.gov/rest/json/cpes/2.0?cpeMatchString=" + urllib.parse.quote(cpe_match_string) + "&resultsPerPage=5"
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode("utf-8")), url


# (product_name, cpeMatchString prefix -- no trailing version, to confirm the pair itself is a
# real dictionary entry) -- the 53 IDENTIFIED_CPE rows where golden-300.csv and job 168 agreed,
# derived from test-data/golden-300.csv x /tmp/job168_results.csv.
CANDIDATES = [
    ("7-Zip", "cpe:2.3:a:7-zip:7-zip"),
    ("Notepad++", "cpe:2.3:a:don_ho:notepad\\+\\+"),
    ("VLC media player", "cpe:2.3:a:videolan:vlc_media_player"),
    ("Mozilla Firefox", "cpe:2.3:a:mozilla:firefox"),
    ("Google Chrome", "cpe:2.3:a:google:chrome"),
    ("Wireshark", "cpe:2.3:a:wireshark:wireshark"),
    ("PuTTY", "cpe:2.3:a:simon_tatham:putty"),
    ("WinRAR", "cpe:2.3:a:rarlab:winrar"),
    ("TeamViewer", "cpe:2.3:a:teamviewer:teamviewer"),
    ("Skype", "cpe:2.3:a:microsoft:skype"),
    ("Docker Desktop", "cpe:2.3:a:docker:docker_desktop"),
    ("Postman", "cpe:2.3:a:postman:postman"),
    ("IntelliJ IDEA", "cpe:2.3:a:jetbrains:intellij_idea"),
    ("Eclipse IDE", "cpe:2.3:a:eclipse:eclipse_ide"),
    ("MySQL Workbench", "cpe:2.3:a:oracle:mysql_workbench"),
    ("GIMP", "cpe:2.3:a:gimp:gimp"),
    ("Git for Windows", "cpe:2.3:a:git_for_windows_project:git_for_windows"),
    ("WinSCP", "cpe:2.3:a:winscp:winscp"),
    ("FileZilla", "cpe:2.3:a:filezilla-project:filezilla"),
    ("KeePass", "cpe:2.3:a:keepass:keepass"),
    ("CCleaner", "cpe:2.3:a:piriform:ccleaner"),
    ("Malwarebytes", "cpe:2.3:a:malwarebytes:malwarebytes"),
    ("Kaspersky Total Security", "cpe:2.3:a:kaspersky:total_security"),
    ("McAfee Total Protection", "cpe:2.3:a:mcafee:total_protection"),
    ("Sophos Endpoint Protection", "cpe:2.3:a:sophos:endpoint_protection"),
    ("Symantec Endpoint Protection", "cpe:2.3:a:broadcom:symantec_endpoint_protection"),
    ("Citrix Workspace App", "cpe:2.3:a:citrix:workspace_app"),
    ("VMware Workstation Pro", "cpe:2.3:a:vmware:workstation_pro"),
    ("Microsoft Office", "cpe:2.3:a:microsoft:office"),
    ("PostgreSQL", "cpe:2.3:a:postgresql:postgresql"),
    ("Python", "cpe:2.3:a:python:python"),
    ("OpenSSL", "cpe:2.3:a:openssl:openssl"),
    ("nginx", "cpe:2.3:a:igor_sysoev:nginx"),
    ("Apache HTTP Server", "cpe:2.3:a:apache:http_server"),
    ("MongoDB", "cpe:2.3:a:mongodb:mongodb"),
    ("Jenkins", "cpe:2.3:a:cloudbees:jenkins"),
    ("GitLab", "cpe:2.3:a:gitlab:gitlab"),
    ("Grafana", "cpe:2.3:a:grafana:grafana"),
    ("Splunk", "cpe:2.3:a:splunk:splunk"),
    ("Adobe Photoshop", "cpe:2.3:a:adobe:photoshop"),
    ("Adobe Illustrator", "cpe:2.3:a:adobe:illustrator"),
    ("AutoCAD", "cpe:2.3:a:autodesk:autocad"),
    ("SolidWorks", "cpe:2.3:a:3ds:solidworks"),
    ("Ansible", "cpe:2.3:a:ansibleworks:ansible"),
    ("Microsoft Visual Studio", "cpe:2.3:a:microsoft:visual_studio"),
    ("WinZip", "cpe:2.3:a:winzip:winzip"),
    ("Total Commander", "cpe:2.3:a:ghisler:total_commander"),
    ("HashiCorp Terraform", "cpe:2.3:a:hashicorp:terraform"),
    ("IrfanView", "cpe:2.3:a:irfanview:irfanview"),
    ("Everything", "cpe:2.3:a:voidtools:everything"),
    ("ImgBurn", "cpe:2.3:a:imgburn:imgburn"),
    ("PDF-XChange Editor", "cpe:2.3:a:pdf-xchange:pdf-xchange_editor"),
    ("ExifTool", "cpe:2.3:a:exiftool_project:exiftool"),
]

assert len(CANDIDATES) == 53, f"expected 53 candidates, got {len(CANDIDATES)}"

out_path = "test-data/golden300_cpe_matchstring_results.tsv"
results = []
with open(out_path, "a") as out:
    for label, prefix in CANDIDATES:
        try:
            data, url = match(prefix)
            total = data.get("totalResults", 0)
            line = f"=== {label} ({prefix}) === total={total} url={url}"
            print(line)
            out.write(line + "\n")
            results.append((label, prefix, total))
        except Exception as e:
            line = f"=== {label} ({prefix}) === ERROR {type(e).__name__}: {e}"
            print(line)
            out.write(line + "\n")
            results.append((label, prefix, "ERROR"))
        out.flush()
        time.sleep(SLEEP_S)

    zero_or_error = [r for r in results if r[2] == 0 or r[2] == "ERROR"]
    summary = (f"\n{len(results)} checked, {len(zero_or_error)} with totalResults=0 or ERROR "
               f"(would mean a fabricated/non-existent CPE):")
    print(summary)
    out.write(summary + "\n")
    for r in zero_or_error:
        line = f"   {r}"
        print(line)
        out.write(line + "\n")

print(f"\nAppended to {out_path}")
