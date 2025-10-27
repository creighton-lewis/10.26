#!/usr/bin/env python3
"""
nmap_scan_report.py
    Parses an Nmap XML file, prints all the usual info and, for every
    open port that has a “vulners” NSE script result, lists the CVE IDs
    and a short description fetched from NVD.

    The script is deliberately minimal – it uses only the standard library
    plus `requests` (you may need to `pip install requests`).
"""

# --------------------------------------------------------------------
# Imports
# --------------------------------------------------------------------
import re
import sys
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional

try:
    import requests    # pip install requests
except ImportError:      # pragma: no cover - defensive
    print("The script requires the *requests* package – install with:\n    pip install requests")
    sys.exit(1)

# --------------------------------------------------------------------
# Helpers – NVD query (keyword search)
# --------------------------------------------------------------------
_NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def _get_cve_summary(cve_id: str) -> Optional[str]:
    """
    Return a one‑line description of *cve_id* from the NVD.

    Uses the (cheap) keyword search endpoint.  If the request fails
    or the CVE is not found, returns None.
    """
    params = {"keywordSearch": cve_id}
    try:
        resp = requests.get(_NVD_BASE_URL, params=params, timeout=5)
    except Exception:
        return None

    if resp.status_code != 200:
        return None

    data = resp.json()
    items = data.get("results", {}).get("CVE_Items", [])
    if not items:
        return None

    # Grab the first available description – usually the first one is good enough.
    desc_data = items[0].get("cve", {}).get("description", {}).get("description_data", [{}])
    description = desc_data[0].get("value", "").strip()
    if description:
        return description.replace("\n", " ")  # keep it one‑liner
    return None


# --------------------------------------------------------------------
# Main parser – unchanged except for the CVE block
# --------------------------------------------------------------------
class NmapParse():
    HIGH_RISK_PORTS = {
    '21': 'FTP - File Transfer Protocol (often unencrypted)',
    '23': 'Telnet - Unencrypted remote access',
    '25': 'SMTP - Email transfer (may allow relay)',
    '445': 'SMB - Windows file sharing (potential target for worms)',
    '3389': 'RDP - Remote Desktop Protocol (target for brute force)',
    '1433': 'MSSQL - Microsoft SQL Server',
    '3306': 'MySQL - Database access',
    '5432': 'PostgreSQL - Database access'
}

    def parse(xml_file: str) -> bool:
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            # ---- Scan meta ---------------------------------------------
            print("Nmap Scan Report")
            print("=" * 50)
            print(f"Scan started at: {root.get('startstr')}")
            print(f"Nmap version: {root.get('version')}")
            print(f"Nmap command: {root.get('args')}")
            print("=" * 50)

            # ---- Per‑host loop ------------------------------------------
            for host in root.findall("host"):

                # ----- IP addresses ---------------------------------------
                for addr in host.findall("address"):
                    if addr.get("addrtype") == "ipv4":
                        ip_address = addr.get("addr")
                        print(f"\nHost: {ip_address}")

                # ----- Hostname --------------------------------------------
                hostnames = host.find("hostnames")
                if hostnames is not None:
                    for hostname in hostnames.findall("hostname"):
                        print(f"Hostname: {hostname.get('name')}")

                # ----- Status -----------------------------------------------
                status = host.find("status")
                if status is not None:
                    print(f"Status: {status.get('state')}")

                # ----- Ports -----------------------------------------------
                ports = host.find("ports")
                if ports is not None:
                    print("\nOpen Ports:")
                    print("-" * 50)
                    print(f"{'PORT':<10}{'STATE':<10}{'SERVICE':<15}{'VERSION'}")
                    print("-" * 50)

                    for port in ports.findall("port"):
                        port_id = port.get("portid")
                        protocol = port.get("protocol")

                        # Port state
                        state_el = port.find("state")
                        port_state = state_el.get("state") if state_el is not None else "unknown"

                        # Skip closed/filtered
                        if port_state != "open":
                            continue

                        # Service details
                        svc_el = port.find("service")
                        if svc_el is not None:
                            svc_name = svc_el.get("name", "")
                            svc_product = svc_el.get("product", "")
                            svc_version = svc_el.get("version", "")
                            svc_info = f"{svc_product} {svc_version}".strip()
                        else:
                            svc_name = ""
                            svc_info = ""

                        # ---- CVE parsing block --------------------------------
                        # Look for <script id="vulners"> inside the port
                        vulners_cves: List[str] = []
                        for scr in port.findall("script"):
                            if scr.get("id") == "vulners":
                                out = scr.get("output", "")
                                vulners_cves += re.findall(r"CVE-\d{4}-\d{4,7}", out)

                        # Print port line
                        print(f"{port_id}/{protocol:<5} {port_state:<10}{svc_name:<15}{svc_info}")

                        # If we found CVEs, print them one line each
                        for cve in vulners_cves:
                            desc = _get_cve_summary(cve)
                            if desc:
                                print(f"    CVE: {cve} – {desc[:80]}…")
                            else:
                                # fallback – just show ID; no description
                                print(f"    CVE: {cve}")

                # ----- OS --------------------------------------------------
                os_el = host.find("os")
                if os_el is not None:
                    print("\nOS Detection:")
                    for osmatch in os_el.findall("osmatch"):
                        print(f"OS: {osmatch.get('name')} (Accuracy: {osmatch.get('accuracy')}%)")

        except ET.ParseError as e:
            print(f"Error parsing XML file: {e}")
            return False
        except Exception as e:
            print(f"Error: {e}")
            return False

        return True


    # --------------------------------------------------------------------
    # Script entry point
    # --------------------------------------------------------------------
    if __name__ == "__main__":
        if len(sys.argv) != 2:
            print(f"Usage: {sys.argv[0]} <nmap_xml_file>")
            sys.exit(1)

        xml_file = sys.argv[1]
        if not parse(xml_file):
            sys.exit(1)
