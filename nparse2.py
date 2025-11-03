#Uses trickest wordlist
import re
import time
import sys
import subprocess
from rich.console import Console
console = Console()
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
def get_cve_summary(cve_id:str) -> Optional[str]:
    cve = cve_id
    year = cve_id.split("-")[1]
    str(year)
    url  = "https://raw.githubusercontent.com/trickest/cve/refs/heads/main/{year}/{cve}.md"
    r  = requests.get(url, timeout=10)
    if r.status_code == 200:
        console.print(f"[bold green]Trickest URL found for {cve}[/bold green]")
        console.print(r.text)
    if r.status_code != 200:
        return None 
    data = r.json()
    items = data.get("results", {}).get("CVE_ItemS",[])
    if not items:
        return None

    desc_data = items[0].get("cve", {}).get("description", {}).get(
        "description_data", [{}]
    )
    description = desc_data[0].get("value", "").strip()
    return description.replace("\n", " ") if description else None
                    
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
                                for cve_id in vulners_cves:
                                    desc = get_cve_summary(cve_id)
                                    if desc:
                                        print(f"    {cve_id} – {desc[:80]}…")
                                    else:
                                        print(f"    {cve_id}")

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
                #----Automated Exploit Finder -----------------------
                
                def results():
                    cves = re.findall(r"CVE-\d{4}-\d{4,7}", out)
                    print(cves) # this is only thing that returns a value
                results()
                """
                #(xml_file:Path | str) -> Optional[List[Dict[str,Any]]]:
                    keyword = print(svc_product)
                    version = svc_version 
                    combo=f"{keyword}_{version}"
                    try:
                        subprocess.run(['uv','run', 'main.py' , '-k' , keyword, '--cvesearch']) 
                    except:
                        console.print("Unable to run processes")
                results()
                """

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
