#!/usr/bin/env python3
import re
import os 
import sys 
import pathlib
from collections import defaultdict

INPUT  = os.path.exists("xml_docs/xml")  # 👉 the file you just pasted
OUTPUT = f"{INPUT}Test"

# ------------------------------------------------------------------
# 1.  Walk the file, remember the current host, and collect CVEs
# ------------------------------------------------------------------
host_cves: defaultdict[str, set[str]] = defaultdict(set)
cur_host = None

with open(INPUT, "r", encoding="utf-8") as fh:
    for line in fh:
        # Detect a new host line – “Host: 127.0.0.1”
        m = re.match(r"^Host:\s+(.+)", line)
        if m:
            cur_host = m.group(1).strip()
            continue

        # Detect a CVE line (indentation is insignificant)
        m = re.match(r"^\s*#?\s*CVE:\s+(CVE-\d{4}-\d{4,7})", line)
        if m and cur_host:
            host_cves[cur_host].add(m.group(1))
            continue

# ------------------------------------------------------------------
# 2.  Dump the grouped CVEs to a new file
# ------------------------------------------------------------------
with open(OUTPUT, "w", encoding="utf-8") as fh:
    for host, cves in host_cves.items():
        fh.write(f"{host}:\n")
        for cve in sorted(cves):
            fh.write(f"    {cve}\n")
        fh.write("\n")

print(f"✓  CVEs grouped by host → {OUTPUT}")
