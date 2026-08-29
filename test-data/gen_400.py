#!/usr/bin/env python3
"""Generates test-data/real-400.csv: 400-row realistic test job (240 non-registry / 160
registry-ecosystem products), with 26 deliberate name-variance pairs woven in (20
non-registry + 6 registry), per the 2026-08-25 AI-tier validation task. Required columns:
product_name,version,vendor,usage_text,install_url (identity ColumnMapping fast path).

usage_text policy (fixed 2026-08-25 per senior-engineer review — see
test-data/real-400.design.md and docs/spec/test-design-policy.md P2): every row's
usage_text is either (a) hand-written and product-specific, for the 26 name-variance
pairs, or (b) drawn from a small per-product-category (non-registry) or per-ecosystem
(registry) template that is true of every product mapped to it. No round-robin pool of
canned strings is used. Every non-registry product name must have an explicit category
mapping below (enforced by assertion) so a reviewer can trace why any given row has the
text it has.
"""
import csv
import os

rows = []  # (product_name, version, vendor, usage_text, install_url)


def add(name, version, vendor, usage_text):
    rows.append((name, version, vendor, usage_text, ""))


# ---------------------------------------------------------------------------
# NON-REGISTRY (target 240 rows): 20 name-variance pairs (40 rows) + 150
# distinct primary products (150 rows) + 50 of those w/ a second older-version
# row (50 rows) = 240.
# ---------------------------------------------------------------------------

# Each entry: (usage_text, (name_a, version_a, vendor_a), (name_b, version_b, vendor_b)).
# usage_text is shared across both members of a pair because both names denote the same
# real-world product; hand-written per pair rather than category-templated, since these
# are the deliberate name-variance/collision adversarial class.
VARIANCE_PAIRS_NONREG = [
    ("used as the primary code editor by developers on the team",
     ("Visual Studio Code", "1.78.2", "Microsoft"), ("VS Code", "1.77.3", "Microsoft")),
    ("used to compress and extract .zip/.7z archive files",
     ("7-Zip", "21.07", "Igor Pavlov"), ("7zip", "19.00", "Igor Pavlov")),
    ("used as a lightweight text/code editor for quick file edits",
     ("Notepad++", "8.5.4", "Don Ho"), ("notepad-plus-plus", "8.4.1", "Don Ho")),
    ("used for team chat, video meetings, and file collaboration",
     ("Microsoft Teams", "1.6.00.13473", "Microsoft"), ("Teams", "1.5.00.28567", "Microsoft")),
    ("used as the default web browser on employee workstations",
     ("Google Chrome", "113.0.5672.127", "Google"), ("Chrome", "112.0.5615.137", "Google")),
    ("used as an alternative web browser on employee workstations",
     ("Mozilla Firefox", "113.0", "Mozilla"), ("Firefox", "112.0.2", "Mozilla")),
    ("used to run and test virtual machines locally",
     ("VMware Workstation Pro", "17.0.0", "VMware"), ("VMware Workstation", "16.2.4", "VMware")),
    ("used for external and internal video meetings",
     ("Zoom", "5.14.5", "Zoom Video Communications"), ("Zoom Client", "5.13.0", "Zoom Video Communications")),
    ("used for team chat and channel-based collaboration",
     ("Slack", "4.29.149", "Slack Technologies"), ("Slack desktop", "4.28.171", "Slack Technologies")),
    ("used to transfer files to and from servers via FTP/SFTP",
     ("FileZilla", "3.63.2", "FileZilla Project"), ("FileZilla Client", "3.62.0", "FileZilla Project")),
    ("used as a set of Windows productivity utilities (window management, quick file rename, etc.)",
     ("Microsoft PowerToys", "0.70.0", "Microsoft"), ("PowerToys", "0.68.1", "Microsoft")),
    ("used to view, fill, and sign PDF documents",
     ("Adobe Acrobat Reader DC", "23.003.20244", "Adobe"), ("Acrobat Reader", "22.003.20282", "Adobe")),
    ("used to run virtual machines for local testing",
     ("VirtualBox", "7.0.8", "Oracle"), ("Oracle VM VirtualBox", "6.1.44", "Oracle")),
    ("used as the default web browser on Windows workstations",
     ("Microsoft Edge", "113.0.1774.50", "Microsoft"), ("Edge", "112.0.1722.58", "Microsoft")),
    ("used as the desktop email client for corporate email",
     ("Mozilla Thunderbird", "102.10.0", "Mozilla"), ("Thunderbird", "91.9.0", "Mozilla")),
    ("used to play local video and audio files",
     ("VLC media player", "3.0.18", "VideoLAN"), ("VLC", "3.0.16", "VideoLAN")),
    ("used for raster image editing and photo retouching",
     ("GIMP", "2.10.34", "GIMP Team"), ("GNU Image Manipulation Program", "2.10.30", "GIMP Team")),
    ("used to build and run containers during local development",
     ("Docker Desktop", "4.19.0", "Docker Inc"), ("Docker for Windows", "2.3.0.5", "Docker Inc")),
    ("used to store and manage passwords in an encrypted local database",
     ("KeePass", "2.53", "Dominik Reichl"), ("KeePass Password Safe", "2.52", "Dominik Reichl")),
    ("used to compress and extract .rar/.zip archive files",
     ("WinRAR", "6.11", "win.rar GmbH"), ("Win RAR", "6.02", "win.rar GmbH")),
]

for usage_text, a, b in VARIANCE_PAIRS_NONREG:
    add(a[0], a[1], a[2], usage_text)
    add(b[0], b[1], b[2], usage_text)

PRIMARY_150 = [
    ("Wireshark", "4.0.5", "Wireshark Foundation"),
    ("PuTTY", "0.78", "Simon Tatham"),
    ("OBS Studio", "29.1.3", "OBS Project"),
    ("Audacity", "3.3.3", "Audacity Team"),
    ("Git for Windows", "2.40.0", "Git for Windows Project"),
    ("TeamViewer", "15.42.6", "TeamViewer"),
    ("Postman", "10.13.4", "Postman Inc"),
    ("Sublime Text", "4.4143", "Sublime HQ"),
    ("WinSCP", "5.21.7", "Martin Prikryl"),
    ("Everything", "1.4.1.1024", "voidtools"),
    ("CCleaner", "6.11", "Piriform"),
    ("Discord", "0.0.278", "Discord Inc"),
    ("Steam", "2023.4.13", "Valve"),
    ("Blender", "3.5.1", "Blender Foundation"),
    ("Inkscape", "1.2.2", "Inkscape Project"),
    ("LibreOffice", "7.5.3", "The Document Foundation"),
    ("HandBrake", "1.6.1", "HandBrake Team"),
    ("Rufus", "3.22", "Pete Batard"),
    ("balenaEtcher", "1.18.11", "balena"),
    ("qBittorrent", "4.5.3", "qBittorrent Project"),
    ("Transmission", "4.0.3", "Transmission Project"),
    ("Krita", "5.1.5", "Krita Foundation"),
    ("Skype", "8.96.0.208", "Microsoft"),
    ("Dropbox", "178.4.5442", "Dropbox Inc"),
    ("Evernote", "10.60.5", "Evernote Corp"),
    ("Adobe Photoshop", "24.5.0", "Adobe"),
    ("Adobe Illustrator", "27.5", "Adobe"),
    ("AnyDesk", "7.0.14", "AnyDesk Software"),
    ("Malwarebytes", "4.5.23", "Malwarebytes"),
    ("Notion", "2.0.44", "Notion Labs"),
    ("Foxit Reader", "12.1.3", "Foxit Software"),
    ("WinZip", "27.0", "Corel"),
    ("Ghostscript", "10.01.1", "Artifex Software"),
    ("Cisco AnyConnect", "4.10.06079", "Cisco"),
    ("Citrix Workspace", "2305", "Citrix"),
    ("Paint.NET", "5.0.11", "dotPDN LLC"),
    ("XAMPP", "8.2.4", "Apache Friends"),
    ("Node.js", "18.16.0", "OpenJS Foundation"),
    ("Python", "3.11.3", "Python Software Foundation"),
    ("Java SE (Oracle JDK)", "17.0.7", "Oracle"),
    ("FileZilla Server", "1.7.1", "FileZilla Project"),
    ("Total Commander", "10.52", "Ghisler Software"),
    ("WinDirStat", "1.1.2", "WinDirStat Project"),
    ("Process Explorer", "17.04", "Microsoft Sysinternals"),
    ("Process Monitor", "3.96", "Microsoft Sysinternals"),
    ("CPU-Z", "2.06", "CPUID"),
    ("GPU-Z", "2.55.0", "TechPowerUp"),
    ("HWiNFO", "7.44", "REALiX"),
    ("Speccy", "1.32", "Piriform"),
    ("Recuva", "1.53", "Piriform"),
    ("Defraggler", "2.22", "Piriform"),
    ("Advanced IP Scanner", "2.5.4594", "Famatech"),
    ("Angry IP Scanner", "3.9.1", "Angry IP Scanner Project"),
    ("Nmap", "7.94", "Nmap Project"),
    ("Burp Suite Community Edition", "2023.4.2", "PortSwigger"),
    ("OWASP ZAP", "2.12.0", "OWASP"),
    ("Fiddler Classic", "5.0.20204", "Progress Telerik"),
    ("MobaXterm", "23.1", "Mobatek"),
    ("Cyberduck", "8.6.2", "iterate GmbH"),
    ("WinMerge", "2.16.32", "WinMerge Project"),
    ("Beyond Compare", "4.4.7", "Scooter Software"),
    ("DBeaver", "23.0.5", "DBeaver Corp"),
    ("MySQL Workbench", "8.0.33", "Oracle"),
    ("pgAdmin 4", "7.3", "The pgAdmin Development Team"),
    ("Insomnia", "2023.4.0", "Kong Inc"),
    ("Tableau Desktop", "2023.1", "Tableau Software"),
    ("Microsoft Visio", "2021", "Microsoft"),
    ("Microsoft Project", "2021", "Microsoft"),
    ("Microsoft Office", "2021", "Microsoft"),
    ("Adobe Premiere Pro", "23.4.0", "Adobe"),
    ("Adobe After Effects", "23.4.0", "Adobe"),
    ("Adobe InDesign", "18.4.0", "Adobe"),
    ("Adobe XD", "55.1.12", "Adobe"),
    ("Figma", "116.16.4", "Figma Inc"),
    ("Sketch", "96", "Sketch B.V."),
    ("Camtasia", "2023.0.1", "TechSmith"),
    ("Snagit", "2023.0.1", "TechSmith"),
    ("ShareX", "15.0.0", "ShareX Team"),
    ("Greenshot", "1.3.274", "Greenshot Project"),
    ("IrfanView", "4.62", "Irfan Skiljan"),
    ("XnView", "2.51.5", "XnSoft"),
    ("FastStone Image Viewer", "7.7", "FastStone Soft"),
    ("Adobe Bridge", "13.0.3", "Adobe"),
    ("CorelDRAW", "2023", "Corel"),
    ("AutoCAD", "2023", "Autodesk"),
    ("SketchUp", "2023", "Trimble"),
    ("Unity Hub", "3.4.2", "Unity Technologies"),
    ("Unreal Engine", "5.2.0", "Epic Games"),
    ("Godot Engine", "4.0.3", "Godot Foundation"),
    ("Visual Studio 2022", "17.6.0", "Microsoft"),
    ("IntelliJ IDEA", "2023.1", "JetBrains"),
    ("PyCharm", "2023.1", "JetBrains"),
    ("WebStorm", "2023.1", "JetBrains"),
    ("Eclipse IDE", "2023-03", "Eclipse Foundation"),
    ("NetBeans", "17", "Apache Software Foundation"),
    ("Android Studio", "2022.2.1", "Google"),
    ("Xcode", "14.3", "Apple"),
    ("Vim", "9.0", "Vim Project"),
    ("Emacs", "28.2", "Free Software Foundation"),
    ("Atom", "1.60.0", "GitHub"),
    ("Brackets", "2.1.4", "Adobe"),
    ("Redis Desktop Manager", "0.9.3", "RDM Dev Team"),
    ("RabbitMQ", "3.11.15", "VMware"),
    ("Apache HTTP Server", "2.4.57", "Apache Software Foundation"),
    ("Nginx", "1.24.0", "Nginx Inc"),
    ("Apache Tomcat", "10.1.7", "Apache Software Foundation"),
    ("WAMP Server", "3.3.0", "WampServer Project"),
    ("MAMP", "6.8", "Appsolute GmbH"),
    ("Redis", "7.0.11", "Redis Ltd"),
    ("MongoDB Compass", "1.38.2", "MongoDB Inc"),
    ("PowerShell", "7.3.4", "Microsoft"),
    ("Windows Terminal", "1.17.11461.0", "Microsoft"),
    ("Cmder", "1.3.20", "Cmder Project"),
    ("ConEmu", "230724", "Maximus5"),
    ("Hyper", "3.4.1", "Vercel"),
    ("iTerm2", "3.4.19", "iTerm2 Project"),
    ("Termius", "8.5.0", "Termius"),
    ("SecureCRT", "9.4.2", "VanDyke Software"),
    ("Royal TS", "7.0.0", "code4ward.net"),
    ("Remote Desktop Manager", "2023.1.30", "Devolutions"),
    ("UltraVNC", "1.4.3.0", "UltraVNC Project"),
    ("TightVNC", "2.8.81", "GlavSoft"),
    ("RealVNC Viewer", "6.22.826", "RealVNC"),
    ("Chrome Remote Desktop", "112.0", "Google"),
    ("Parsec", "150.0", "Parsec Cloud"),
    ("NoMachine", "8.6.1", "NoMachine"),
    ("Splashtop Business", "3.5.9", "Splashtop Inc"),
    ("Webroot SecureAnywhere", "9.0.32", "Webroot"),
    ("Bitdefender Total Security", "27.0.19", "Bitdefender"),
    ("Norton 360", "22.23.1", "NortonLifeLock"),
    ("Kaspersky Total Security", "21.3", "Kaspersky"),
    ("ESET NOD32 Antivirus", "16.2", "ESET"),
    ("AVG AntiVirus Free", "23.5", "AVG Technologies"),
    ("Avast Free Antivirus", "23.5", "Avast"),
    ("McAfee Total Protection", "16.0.53", "McAfee"),
    ("Sophos Home", "4.4.0", "Sophos"),
    ("GlassWire", "3.3.446", "GlassWire"),
    ("NetLimiter", "5.3.1", "Locktime Software"),
    ("SolarWinds Network Performance Monitor", "2023.2", "SolarWinds"),
    ("PRTG Network Monitor", "23.1.82", "Paessler"),
    ("Nagios Core", "4.5.0", "Nagios Enterprises"),
    ("Zabbix Agent", "6.4.3", "Zabbix SIA"),
    ("Grafana", "9.5.2", "Grafana Labs"),
    ("Prometheus", "2.44.0", "Prometheus Project"),
    ("Jenkins", "2.401.1", "Jenkins Project"),
    ("GitLab Runner", "16.0.0", "GitLab Inc"),
    ("SourceTree", "3.4.14", "Atlassian"),
    ("GitKraken", "9.0.1", "Axosoft"),
    ("TortoiseGit", "2.15.0", "TortoiseGit Project"),
    ("TortoiseSVN", "1.14.5", "TortoiseSVN Project"),
]

assert len(PRIMARY_150) == 150, len(PRIMARY_150)

# Category templates: each key's text must be true of every product mapped to it. This
# is the "reasonable middle ground" level of specificity (task-directed) — correct at the
# product-category level, never generic filler reused across unrelated categories.
CATEGORY_TEXT = {
    "net_monitor": "used by the network/ops team to monitor traffic and diagnose connectivity issues",
    "ssh_client": "used as an SSH/terminal client to connect to remote servers",
    "screen_recording": "used to record or stream the screen for demos, training, or troubleshooting",
    "audio_editor": "used for audio recording and editing",
    "vcs_cli": "used to run Git version control commands from the command line",
    "remote_desktop": "used to remotely connect to and control other machines",
    "api_client": "used to build and test HTTP API requests during development",
    "text_editor": "used as a lightweight text/code editor by developers",
    "ftp_sftp_client": "used to transfer files to and from remote servers via FTP/SFTP",
    "file_search": "used to quickly search for files across local drives",
    "hw_diagnostics": "used to inspect hardware and system configuration information",
    "process_diagnostics": "used to inspect and troubleshoot running processes and system activity",
    "disk_cleanup": "used to clean up disk space, defragment drives, or recover deleted files",
    "boot_media": "used to create bootable USB installation media",
    "comm_chat": "used for internal team chat and messaging",
    "game_platform": "used to install, launch, and manage PC games",
    "3d_creative": "used for 3D modeling and animation",
    "vector_graphics": "used for vector illustration and page layout",
    "office_suite": "used for word processing, spreadsheets, and presentations",
    "video_transcode": "used to transcode and convert video files",
    "torrent_client": "used to download files via BitTorrent",
    "image_editor": "used for raster image editing and digital painting",
    "comm_video": "used for internal video conferencing and screen sharing",
    "cloud_sync": "used to sync files to cloud storage",
    "note_taking": "used for internal note-taking and knowledge management",
    "antivirus": "used as endpoint antivirus/security software on workstations",
    "pdf_reader": "used to view and annotate PDF documents",
    "archiver": "used to compress and extract archive files",
    "print_pdf_processing": "used to process PostScript and PDF files as part of a document workflow",
    "vpn_client": "used to connect to the corporate VPN",
    "virtual_app_access": "used to access virtualized corporate applications and desktops",
    "runtime": "used as the language runtime for running internal applications",
    "ftp_sftp_server": "used to host an FTP/SFTP server for internal file transfers",
    "file_manager": "used as a dual-pane file manager for local file management",
    "net_scanner": "used to scan and inventory devices on the local network",
    "security_scanner": "used by the security team to test and debug web application traffic",
    "diff_merge": "used to compare and merge files and folders",
    "db_client": "used to connect to and manage databases",
    "bi_tool": "used for data visualization and business intelligence reporting",
    "diagramming": "used to create diagrams and flowcharts",
    "project_mgmt": "used for project scheduling and resource management",
    "video_editor": "used for video recording, editing, and visual effects",
    "design_tool": "used for UI/UX design and prototyping",
    "screen_capture": "used to capture and annotate screenshots",
    "image_viewer": "used to view and organize image files",
    "cad_3d": "used for CAD and 3D modeling",
    "game_engine": "used for game development",
    "ide": "used as a code editor/IDE by developers",
    "message_queue": "used as the message broker or in-memory data store backing an internal service",
    "web_server": "used to serve or host web applications",
    "shell": "used as the command-line shell for administration and scripting",
    "monitoring": "used by the ops team to monitor infrastructure health and metrics",
    "ci_cd": "used to run automated builds on a CI/CD agent",
    "vcs_gui": "used as a Git GUI client for source control by the engineering team",
}

NONREGISTRY_CATEGORY = {
    "Wireshark": "net_monitor",
    "PuTTY": "ssh_client",
    "OBS Studio": "screen_recording",
    "Audacity": "audio_editor",
    "Git for Windows": "vcs_cli",
    "TeamViewer": "remote_desktop",
    "Postman": "api_client",
    "Sublime Text": "text_editor",
    "WinSCP": "ftp_sftp_client",
    "Everything": "file_search",
    "CCleaner": "disk_cleanup",
    "Discord": "comm_chat",
    "Steam": "game_platform",
    "Blender": "3d_creative",
    "Inkscape": "vector_graphics",
    "LibreOffice": "office_suite",
    "HandBrake": "video_transcode",
    "Rufus": "boot_media",
    "balenaEtcher": "boot_media",
    "qBittorrent": "torrent_client",
    "Transmission": "torrent_client",
    "Krita": "image_editor",
    "Skype": "comm_video",
    "Dropbox": "cloud_sync",
    "Evernote": "note_taking",
    "Adobe Photoshop": "image_editor",
    "Adobe Illustrator": "vector_graphics",
    "AnyDesk": "remote_desktop",
    "Malwarebytes": "antivirus",
    "Notion": "note_taking",
    "Foxit Reader": "pdf_reader",
    "WinZip": "archiver",
    "Ghostscript": "print_pdf_processing",
    "Cisco AnyConnect": "vpn_client",
    "Citrix Workspace": "virtual_app_access",
    "Paint.NET": "image_editor",
    "XAMPP": "web_server",
    "Node.js": "runtime",
    "Python": "runtime",
    "Java SE (Oracle JDK)": "runtime",
    "FileZilla Server": "ftp_sftp_server",
    "Total Commander": "file_manager",
    "WinDirStat": "disk_cleanup",
    "Process Explorer": "process_diagnostics",
    "Process Monitor": "process_diagnostics",
    "CPU-Z": "hw_diagnostics",
    "GPU-Z": "hw_diagnostics",
    "HWiNFO": "hw_diagnostics",
    "Speccy": "hw_diagnostics",
    "Recuva": "disk_cleanup",
    "Defraggler": "disk_cleanup",
    "Advanced IP Scanner": "net_scanner",
    "Angry IP Scanner": "net_scanner",
    "Nmap": "security_scanner",
    "Burp Suite Community Edition": "security_scanner",
    "OWASP ZAP": "security_scanner",
    "Fiddler Classic": "security_scanner",
    "MobaXterm": "ssh_client",
    "Cyberduck": "ftp_sftp_client",
    "WinMerge": "diff_merge",
    "Beyond Compare": "diff_merge",
    "DBeaver": "db_client",
    "MySQL Workbench": "db_client",
    "pgAdmin 4": "db_client",
    "Insomnia": "api_client",
    "Tableau Desktop": "bi_tool",
    "Microsoft Visio": "diagramming",
    "Microsoft Project": "project_mgmt",
    "Microsoft Office": "office_suite",
    "Adobe Premiere Pro": "video_editor",
    "Adobe After Effects": "video_editor",
    "Adobe InDesign": "vector_graphics",
    "Adobe XD": "design_tool",
    "Figma": "design_tool",
    "Sketch": "design_tool",
    "Camtasia": "screen_recording",
    "Snagit": "screen_capture",
    "ShareX": "screen_capture",
    "Greenshot": "screen_capture",
    "IrfanView": "image_viewer",
    "XnView": "image_viewer",
    "FastStone Image Viewer": "image_viewer",
    "Adobe Bridge": "image_viewer",
    "CorelDRAW": "vector_graphics",
    "AutoCAD": "cad_3d",
    "SketchUp": "cad_3d",
    "Unity Hub": "game_engine",
    "Unreal Engine": "game_engine",
    "Godot Engine": "game_engine",
    "Visual Studio 2022": "ide",
    "IntelliJ IDEA": "ide",
    "PyCharm": "ide",
    "WebStorm": "ide",
    "Eclipse IDE": "ide",
    "NetBeans": "ide",
    "Android Studio": "ide",
    "Xcode": "ide",
    "Vim": "text_editor",
    "Emacs": "text_editor",
    "Atom": "text_editor",
    "Brackets": "text_editor",
    "Redis Desktop Manager": "db_client",
    "RabbitMQ": "message_queue",
    "Apache HTTP Server": "web_server",
    "Nginx": "web_server",
    "Apache Tomcat": "web_server",
    "WAMP Server": "web_server",
    "MAMP": "web_server",
    "Redis": "message_queue",
    "MongoDB Compass": "db_client",
    "PowerShell": "shell",
    "Windows Terminal": "shell",
    "Cmder": "shell",
    "ConEmu": "shell",
    "Hyper": "shell",
    "iTerm2": "shell",
    "Termius": "ssh_client",
    "SecureCRT": "ssh_client",
    "Royal TS": "remote_desktop",
    "Remote Desktop Manager": "remote_desktop",
    "UltraVNC": "remote_desktop",
    "TightVNC": "remote_desktop",
    "RealVNC Viewer": "remote_desktop",
    "Chrome Remote Desktop": "remote_desktop",
    "Parsec": "remote_desktop",
    "NoMachine": "remote_desktop",
    "Splashtop Business": "remote_desktop",
    "Webroot SecureAnywhere": "antivirus",
    "Bitdefender Total Security": "antivirus",
    "Norton 360": "antivirus",
    "Kaspersky Total Security": "antivirus",
    "ESET NOD32 Antivirus": "antivirus",
    "AVG AntiVirus Free": "antivirus",
    "Avast Free Antivirus": "antivirus",
    "McAfee Total Protection": "antivirus",
    "Sophos Home": "antivirus",
    "GlassWire": "net_monitor",
    "NetLimiter": "net_monitor",
    "SolarWinds Network Performance Monitor": "monitoring",
    "PRTG Network Monitor": "monitoring",
    "Nagios Core": "monitoring",
    "Zabbix Agent": "monitoring",
    "Grafana": "monitoring",
    "Prometheus": "monitoring",
    "Jenkins": "ci_cd",
    "GitLab Runner": "ci_cd",
    "SourceTree": "vcs_gui",
    "GitKraken": "vcs_gui",
    "TortoiseGit": "vcs_gui",
    "TortoiseSVN": "vcs_gui",
}

assert len(NONREGISTRY_CATEGORY) == 150, len(NONREGISTRY_CATEGORY)
for _name, _, _ in PRIMARY_150:
    assert _name in NONREGISTRY_CATEGORY, f"no category mapping for {_name!r}"
for _cat in NONREGISTRY_CATEGORY.values():
    assert _cat in CATEGORY_TEXT, f"category {_cat!r} has no template text"


def nonreg_usage_text(name):
    return CATEGORY_TEXT[NONREGISTRY_CATEGORY[name]]


for name, version, vendor in PRIMARY_150:
    add(name, version, vendor, nonreg_usage_text(name))

# 50 of the above (the first 50) also get a second, older version row. Same product, same
# usage text.
OLDER_VERSIONS = {
    "Wireshark": "3.6.15", "PuTTY": "0.76", "OBS Studio": "28.0.0", "Audacity": "3.2.5",
    "Git for Windows": "2.39.2", "TeamViewer": "15.38.4", "Postman": "10.10.0",
    "Sublime Text": "3.2.2", "WinSCP": "5.19.6", "Everything": "1.4.1.935",
    "CCleaner": "6.05", "Discord": "0.0.273", "Steam": "2023.3.9", "Blender": "3.4.1",
    "Inkscape": "1.1.2", "LibreOffice": "7.4.6", "HandBrake": "1.5.1", "Rufus": "3.21",
    "balenaEtcher": "1.7.9", "qBittorrent": "4.4.5", "Transmission": "3.00", "Krita": "5.0.2",
    "Skype": "8.95.0.407", "Dropbox": "175.4.5178", "Evernote": "10.58.4",
    "Adobe Photoshop": "23.5.0", "Adobe Illustrator": "26.5", "AnyDesk": "6.3.2",
    "Malwarebytes": "4.5.20", "Notion": "2.0.38", "Foxit Reader": "11.2.1", "WinZip": "26.0",
    "Ghostscript": "9.56.1", "Cisco AnyConnect": "4.10.04065", "Citrix Workspace": "2212",
    "Paint.NET": "4.3.12", "XAMPP": "8.1.17", "Node.js": "16.20.0", "Python": "3.10.11",
    "Java SE (Oracle JDK)": "11.0.19", "FileZilla Server": "1.6.1", "Total Commander": "10.00",
    "WinDirStat": "1.1.1", "Process Explorer": "16.45", "Process Monitor": "3.94",
    "CPU-Z": "1.104", "GPU-Z": "2.51.0", "HWiNFO": "7.30", "Speccy": "1.31", "Recuva": "1.52",
}
assert len(OLDER_VERSIONS) == 50, len(OLDER_VERSIONS)

primary_vendor_by_name = {name: vendor for name, _, vendor in PRIMARY_150}
for name, older_version in OLDER_VERSIONS.items():
    add(name, older_version, primary_vendor_by_name[name], nonreg_usage_text(name))

non_registry_count = len(rows)
assert non_registry_count == 240, f"non-registry count = {non_registry_count}"

# ---------------------------------------------------------------------------
# REGISTRY / ECOSYSTEM (target 160 rows): 10 ecosystems x 16 rows, including
# 6 name-variance pairs (12 rows) woven in.
# ---------------------------------------------------------------------------

NPM = [
    ("express", "4.18.2"), ("lodash", "4.17.21"), ("react", "18.2.0"), ("axios", "1.4.0"),
    ("chalk", "5.3.0"), ("commander", "11.0.0"), ("@angular/core", "16.1.0"),
    ("angular", "1.8.3"), ("vue", "3.3.4"), ("webpack", "5.86.0"), ("typescript", "5.1.3"),
    ("eslint", "8.42.0"), ("jest", "29.5.0"), ("react-dom", "18.2.0"), ("moment", "2.29.4"),
    ("uuid", "9.0.0"),
]

PYPI = [
    ("requests", "2.31.0"), ("flask", "2.3.2"), ("numpy", "1.24.3"), ("django", "4.2.1"),
    ("pytest", "7.3.1"), ("click", "8.1.3"), ("Pillow", "9.5.0"), ("beautifulsoup4", "4.12.2"),
    ("bs4", "4.12.2"), ("scipy", "1.10.1"), ("pandas", "2.0.2"), ("sqlalchemy", "2.0.15"),
    ("pyyaml", "6.0"), ("jinja2", "3.1.2"), ("cryptography", "41.0.1"), ("celery", "5.3.1"),
]

NUGET = [
    ("Newtonsoft.Json", "13.0.3"), ("Json.NET", "13.0.1"), ("Serilog", "3.0.1"),
    ("AutoMapper", "12.0.1"), ("Dapper", "2.0.151"), ("Polly", "7.2.4"),
    ("FluentValidation", "11.5.2"), ("MediatR", "12.1.1"), ("NUnit", "3.13.3"),
    ("Moq", "4.20.69"), ("EntityFramework", "6.4.4"),
    ("Microsoft.Extensions.DependencyInjection", "7.0.0"), ("RestSharp", "110.2.0"),
    ("Swashbuckle.AspNetCore", "6.5.0"), ("Hangfire", "1.8.0"), ("StackExchange.Redis", "2.6.122"),
]

RUBYGEMS = [
    ("rails", "7.0.4"), ("sidekiq", "7.1.0"), ("rspec", "3.12.0"), ("devise", "4.9.2"),
    ("puma", "6.2.2"), ("nokogiri", "1.15.1"), ("faraday", "2.7.7"), ("rubocop", "1.50.2"),
    ("capistrano", "3.17.3"), ("sinatra", "3.0.6"), ("bundler", "2.4.13"), ("rack", "3.0.7"),
    ("jekyll", "4.3.2"), ("httparty", "0.21.0"), ("pry", "0.14.2"), ("rake", "13.0.6"),
]

CRATES = [
    ("serde", "1.0.163"), ("tokio", "1.28.1"), ("clap", "4.3.0"), ("rand", "0.8.5"),
    ("reqwest", "0.11.18"), ("actix-web", "4.3.1"), ("regex", "1.8.3"), ("anyhow", "1.0.71"),
    ("Tokio", "1.28.0"), ("thiserror", "1.0.40"), ("log", "0.4.18"), ("serde_json", "1.0.96"),
    ("futures", "0.3.28"), ("hyper", "0.14.26"), ("rayon", "1.7.0"), ("bytes", "1.4.0"),
]

PACKAGIST = [
    ("monolog/monolog", "3.3.1"), ("symfony/console", "6.2.7"), ("guzzlehttp/guzzle", "7.7.0"),
    ("laravel/framework", "10.10.0"), ("phpunit/phpunit", "10.1.3"), ("doctrine/orm", "2.15.1"),
    ("twig/twig", "3.6.0"), ("nesbot/carbon", "2.66.0"), ("symfony/http-foundation", "6.2.7"),
    ("league/flysystem", "3.15.0"), ("composer/composer", "2.5.5"),
    ("phpoffice/phpspreadsheet", "1.28.0"), ("swiftmailer/swiftmailer", "6.3.0"),
    ("vlucas/phpdotenv", "5.5.0"), ("ramsey/uuid", "4.7.4"), ("firebase/php-jwt", "6.4.0"),
]

HEX = [
    ("phoenix", "1.7.2"), ("ecto", "3.10.1"), ("plug", "1.14.2"), ("jason", "1.4.1"),
    ("cowboy", "2.10.0"), ("ex_doc", "0.29.4"), ("broadway", "1.0.7"), ("absinthe", "1.7.1"),
    ("phoenix_live_view", "0.18.18"), ("telemetry", "1.2.1"), ("gettext", "0.22.1"),
    ("finch", "0.16.0"), ("oban", "2.15.2"), ("credo", "1.7.0"), ("bcrypt_elixir", "3.0.1"),
    ("tesla", "1.7.0"),
]

PUB = [
    ("http", "1.1.0"), ("provider", "6.0.5"), ("dio", "5.3.0"), ("path", "1.8.3"),
    ("shared_preferences", "2.2.0"), ("flutter_bloc", "8.1.3"), ("intl", "0.18.1"),
    ("json_annotation", "4.8.1"), ("get", "4.6.5"), ("riverpod", "2.4.0"),
    ("equatable", "2.0.5"), ("cached_network_image", "3.2.3"), ("url_launcher", "6.1.12"),
    ("sqflite", "2.3.0"), ("rxdart", "0.27.7"), ("connectivity_plus", "4.0.1"),
]

MAVEN = [
    ("com.google.guava:guava", "32.0.1-jre"), ("Guava", "31.1-jre"),
    ("org.apache.commons:commons-lang3", "3.12.0"),
    ("com.fasterxml.jackson.core:jackson-databind", "2.15.1"),
    ("org.springframework:spring-core", "6.0.9"), ("junit:junit", "4.13.2"),
    ("org.slf4j:slf4j-api", "2.0.7"), ("com.google.code.gson:gson", "2.10.1"),
    ("org.apache.httpcomponents:httpclient", "4.5.14"),
    ("org.hibernate:hibernate-core", "6.2.2.Final"),
    ("com.squareup.okhttp3:okhttp", "4.11.0"), ("org.projectlombok:lombok", "1.18.28"),
    ("ch.qos.logback:logback-classic", "1.4.7"), ("org.apache.kafka:kafka-clients", "3.4.0"),
    ("io.netty:netty-all", "4.1.93.Final"), ("com.zaxxer:HikariCP", "5.0.1"),
]

GOPROXY = [
    ("github.com/gin-gonic/gin", "v1.9.1"), ("gin", "v1.9.1"),
    ("github.com/spf13/cobra", "v1.7.0"), ("github.com/stretchr/testify", "v1.8.4"),
    ("github.com/sirupsen/logrus", "v1.9.2"), ("github.com/gorilla/mux", "v1.8.0"),
    ("golang.org/x/crypto", "v0.9.0"), ("github.com/go-redis/redis/v9", "v9.0.5"),
    ("github.com/prometheus/client_golang", "v1.16.0"),
    ("github.com/go-sql-driver/mysql", "v1.7.1"), ("github.com/spf13/viper", "v1.16.0"),
    ("github.com/golang-jwt/jwt/v5", "v5.0.0"), ("github.com/google/uuid", "v1.3.0"),
    ("github.com/aws/aws-sdk-go", "v1.44.279"), ("github.com/labstack/echo/v4", "v4.11.1"),
    ("go.uber.org/zap", "v1.24.0"),
]

# Default per-ecosystem template (true of essentially any package in that ecosystem).
ECOSYSTEM_TEXT = {
    "npm registry": "used as an npm package dependency in a Node.js/JavaScript project's build pipeline",
    "PyPI": "used as a PyPI package dependency in a Python application",
    "NuGet": "used as a NuGet package dependency in a .NET application",
    "RubyGems": "used as a Ruby gem dependency in a Rails/Ruby application",
    "crates.io": "used as a Rust crate dependency pulled in via Cargo",
    "Packagist": "used as a Composer/PHP package dependency in the application",
    "Hex (hex.pm)": "used as an Elixir Hex package dependency in a Phoenix/Elixir application",
    "pub.dev": "used as a Dart/Flutter pub.dev package dependency in a mobile app",
    "Maven Central": "used as a Java/Maven dependency pulled in via the build",
    "Go module proxy": "used as a Go module dependency imported in the codebase",
}

# Hand-written overrides for the 6 registry name-variance/collision pairs — the
# adversarial class for this segment. Both members of a pair share the same text since
# they denote the same (or, for angular/@angular/core, closely related) real product.
REGISTRY_VARIANCE_TEXT = {
    "angular": "used as the front-end JavaScript framework for a web application",
    "@angular/core": "used as the front-end JavaScript framework for a web application",
    "bs4": "used as a Python library to parse and scrape HTML/XML",
    "beautifulsoup4": "used as a Python library to parse and scrape HTML/XML",
    "Newtonsoft.Json": "used as the JSON serialization library in a .NET application",
    "Json.NET": "used as the JSON serialization library in a .NET application",
    "tokio": "used as the async runtime in a Rust application",
    "Tokio": "used as the async runtime in a Rust application",
    "com.google.guava:guava": "used as a Java utility library dependency",
    "Guava": "used as a Java utility library dependency",
    "gin": "used as the HTTP web framework in a Go service",
    "github.com/gin-gonic/gin": "used as the HTTP web framework in a Go service",
}

ECOSYSTEMS = [
    (NPM, "npm registry"), (PYPI, "PyPI"), (NUGET, "NuGet"), (RUBYGEMS, "RubyGems"),
    (CRATES, "crates.io"), (PACKAGIST, "Packagist"), (HEX, "Hex (hex.pm)"),
    (PUB, "pub.dev"), (MAVEN, "Maven Central"), (GOPROXY, "Go module proxy"),
]

for package_list, ecosystem_label in ECOSYSTEMS:
    assert len(package_list) == 16, f"{ecosystem_label} has {len(package_list)} rows"
    for name, version in package_list:
        usage_text = REGISTRY_VARIANCE_TEXT.get(name, ECOSYSTEM_TEXT[ecosystem_label])
        add(name, version, "", usage_text)

total = len(rows)
assert total == 400, f"total rows = {total}"

out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "real-400.csv")
with open(out_path, "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["product_name", "version", "vendor", "usage_text", "install_url"])
    for row in rows:
        w.writerow(row)

print(f"Wrote {total} rows ({non_registry_count} non-registry, {total - non_registry_count} registry) to {out_path}")
