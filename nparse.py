#!/usr/bin/env python3
"""
nmap_scan_report.py
    Parses an Nmap XML file, prints all the usual info and, for every
    open port that has a “vulners” NSE script result, lists the CVE IDs
    and a short description fetched from NVD.

    The script uses only the standard library plus `requests` (you
    may need to `pip install requests`).
"""

# --------------------------------------------------------------------
# Imports
# --------------------------------------------------------------------
import re
import sys
import json
import xmltodict #type ignore
from pathlib import Path
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any

try:
    import requests    # pip install requests
except ImportError:      # pragma: no cover - defensive
    print(
        "The script requires the *requests* package – install with:\n"
        "    pip install requests"
    )
    sys.exit(1)
#What does _NVD_BASE_URl
# --------------------------------------------------------------------
# Helpers – NVD query (keyword search)
# --------------------------------------------------------------------
_NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def _get_cve_summary(cve_id: str) -> Optional[str]:
    """
    Return a one‑liner description of *cve_id* from the NVD.
    Uses the keyword‑search endpoint; returns ``None`` on failure.
    """
    params = {"keywordSearch": cve_id}
    try:
        resp = requests.get(_NVD_BASE_URL, params=params, timeout=5)
    except Exception:          # pragma: no cover
        return None

    if resp.status_code != 200:
        return None

    data = resp.json()
    items = data.get("results", {}).get("CVE_Items", [])
    if not items:
        return None

    desc_data = items[0].get("cve", {}).get("description", {}).get(
        "description_data", [{}]
    )
    description = desc_data[0].get("value", "").strip()
    return description.replace("\n", " ") if description else None


# --------------------------------------------------------------------
# Main parser – returns a list of host infos
# --------------------------------------------------------------------
class NmapParse:
    @staticmethod
    def parse(xml_file: Path | str) -> Optional[List[Dict[str, Any]]]:
        """
        Parse the supplied Nmap XML file and return a **list of host dictionaries**.
        Each host dictionary contains:

        * ``ip``          – IPv4 address
        * ``hostnames``   – list of hostnames
        * ``status``      – host state
        * ``ports``       – list of open‑port dictionaries
          (``portid``, ``protocol``, ``state``, ``service`` , ``product``,
          ``version``, ``cve`` – list of CVE IDs from the *vulners* script).

        On a parsing error ``None`` is returned.
        """
        try:
            tree = ET.parse(str(xml_file))
            root = tree.getroot()

            hosts: List[Dict[str, Any]] = []

            # ---- Scan meta ---------------------------------------------
            print("Nmap Scan Report")
            print("=" * 50)
            print(f"Scan started at: {root.get('startstr')}")
            print(f"Nmap version: {root.get('version')}")
            print(f"Nmap command: {root.get('args')}")
            print("=" * 50)

            # ---- Per‑host loop ------------------------------------------
            for host in root.findall("host"):
                host_info: Dict[str, Any] = {}

                # ----- IP addresses ---------------------------------------
                ip_address = None
                for addr in host.findall("address"):
                    if addr.get("addrtype") == "ipv4":
                        ip_address = addr.get("addr")
                        host_info["ip"] = ip_address
                if ip_address:
                    print(f"\nHost: {ip_address}")

                # ----- Hostname --------------------------------------------
                hostnames = host.find("hostnames")
                hn_list = []
                if hostnames is not None:
                    for hostname in hostnames.findall("hostname"):
                        hn = hostname.get("name")
                        hn_list.append(hn)
                        print(f"Hostname: {hn}")
                host_info["hostnames"] = hn_list

                # ----- Status -----------------------------------------------
                status = host.find("status")
                st = status.get("state") if status is not None else "unknown"
                host_info["status"] = st
                print(f"Status: {st}")

                # ----- Ports -----------------------------------------------
                ports_node = host.find("ports")
                port_list: List[Dict[str, Any]] = []
                if ports_node is not None:
                    print("\nOpen Ports:")
                    print("-" * 50)
                    print(f"{'PORT':<10}{'STATE':<10}{'SERVICE':<15}{'VERSION'}")
                    print("-" * 50)

                    for port in ports_node.findall("port"):
                        portid = port.get("portid")
                        protocol = port.get("protocol")

                        # Port state
                        state_el = port.find("state")
                        port_state = (
                            state_el.get("state") if state_el is not None else "unknown"
                        )
                        if port_state != "open":
                            continue

                        # Service info
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
                        vulners_cves: List[str] = []
                        for scr in port.findall("script"):
                            if scr.get("id") == "vulners":
                                out = scr.get("output", "")
                                vulners_cves += re.findall(r"CVE-\d{4}-\d{4,7}", out)

                        # Print port line
                        print(
                            f"{portid}/{protocol:<5} {port_state:<10}"
                            f"{svc_name:<15}{svc_info}"
                        )

                        # If we found CVEs, print them one line each
                        for cve in vulners_cves:
                            desc = _get_cve_summary(cve)
                            if desc:
                                print(f"    CVE: {cve} – {desc[:80]}…")
                            else:
                                print(f"    CVE: {cve}")

                        # Add to the list that will be returned
                        port_list.append(
                            {
                                "portid": portid,
                                "protocol": protocol,
                                "state": port_state,
                                "service": svc_name,
                                "product": svc_product,
                                "version": svc_version,
                                "cve": vulners_cves,
                            }
                        )

                host_info["ports"] = port_list

                # ----- OS --------------------------------------------------
                os_el = host.find("os")
                os_list = []
                if os_el is not None:
                    print("\nOS Detection:")
                    for osmatch in os_el.findall("osmatch"):
                        os_name = osmatch.get("name")
                        accuracy = osmatch.get("accuracy")
                        os_list.append((os_name, accuracy))
                        print(f"OS: {os_name} (Accuracy: {accuracy}%)")
                host_info["os"] = os_list

                hosts.append(host_info)

        except ET.ParseError as e:
            print(f"Error parsing XML file: {e}", file=sys.stderr)
            return None

        except Exception as e:                     # pragma: no cover
            print(f"Unexpected error: {e}", file=sys.stderr)
            return None

        return hosts


# --------------------------------------------------------------------
# Script entry point
# --------------------------------------------------------------------
def main() -> None:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <nmap_xml_file>")
        sys.exit(1)

    xml_file = Path(sys.argv[1])
    if not xml_file.exists():
        print(f"File not found: {xml_file}", file=sys.stderr)
        sys.exit(1)

    # Parse and retrieve the host data
    hosts = NmapParse.parse(xml_file)
    if hosts is None:
        sys.exit(1)

    # OPTIONAL: do something with the returned data
    # (the script already prints everything, so this is just a placeholder)
    # for host in hosts:
    #     ... (your own processing)


if __name__ == "__main__":
    main()
