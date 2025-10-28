# -*- coding: utf-8 -*-
"""
Output helper class – uses rich for coloured printing.
"""

import re          # kept from the original imports
import os
import json
import pyaml       # type: ignore
from rich.console import Console


class Output:
    """
    Pretty‑printing helper for various API results.
    Uses the Rich library for coloured output.
    """

    def __init__(self):
        # Rich console instance – auto‑interprets markup
        self.console = Console()
        # Collection of results that can later be exported as JSON/YAML
        self.data = []

    # --------------------------------------------------------------------------- #
    #                          Static output helpers                             #
    # --------------------------------------------------------------------------- #
    def banner(self):
        ascii_art = r"""
        _._     _,-'""`-._
        (,-.`._,'(       |\`-/|
            `-.-' \ )-`( , [red]o o[/red]
                `-    \`_`"'-
        [red]SiCat[/red] - The useful [red]exploit[/red] finder
        @justakazh (https://github.com/justakazh/sicat)

        usage : vulny.py --help
        """
        self.console.print(ascii_art)

    def start(self, keyword: str = "", version: str = ""):
        self.console.print("|")
        self.console.print(f"|[yellow]> Starting with Keyword : {keyword} {version}[/yellow]")
        self.console.print("|----------------------------------------")

    # --------------------------------------------------------------------------- #
    #                            API result printing                           #
    # --------------------------------------------------------------------------- #
    def exploitdb(self, content: dict):
        """Show Exploit‑DB results."""
        try:
            results = content.get("data", [])
            if results:
                self.console.print("|")
                self.console.print(f"|[green]+ Exploit-DB Result[/green]")
                self.console.print("|--------------------")

                predata = []
                for data in results:
                    self.console.print(f"|[blue]-[/blue] Title : {data['description'][1]}")
                    self.console.print(f"|[blue]-[/blue] Type  : {data['type_id']}")
                    self.console.print(
                        f"|[blue]-[/blue] Link  : "
                        f"https://www.exploit-db.com/exploits/{data['description'][0]}"
                    )
                    self.console.print("|")
                    self.console.print("|")

                    predata.append(
                        {
                            "title": data["description"][1],
                            "type": data["type_id"],
                            "link": f"https://www.exploit-db.com/exploits/{data['description'][0]}",
                        }
                    )

                self.console.print(
                    f"|[blue]-[/blue] Total Result : [green]{len(results)}[/green] Exploits Found!"
                )
                self.data.append({"exploitdb": predata})
            else:
                self.console.print("|[red]- No result in ExploitDB![/red]")
        except Exception:
            self.console.print("|[red]- Internal Error - No result in ExploitDB![/red]")

    def msfmodule(self, content: list):
        """Show Metasploit module results."""
        try:
            if content:
                self.console.print("|")
                self.console.print(f"|[green]+ Metasploit Module Result[/green]")
                self.console.print("|------------------------------")

                predata = []
                for data in content:
                    self.console.print(f"|[blue]-[/blue] Title : {data['title'].capitalize()}")
                    self.console.print(f"|[blue]-[/blue] Module : {data['module']}")
                    self.console.print(f"|[blue]-[/blue] Link : {data['link']}")
                    self.console.print(f"|[blue]-[/blue] Description : {data['description']}")
                    self.console.print("|")
                    self.console.print("|")

                    predata.append(
                        {"title": data["title"], "module": data["module"], "link": data["link"]}
                    )
                self.console.print(
                    f"|[blue]-[/blue] Total Result : [green]{len(content)}[/green] Modules Found!"
                )
                self.data.append({"msfmodule": predata})
            else:
                self.console.print("|[red]- No result in Metasploit Module![/red]")
        except Exception:
            self.console.print("|[red]- Internal Error - No result in Metasploit Module![/red]")

    def nvddb(self, content: dict):
        """Show National Vulnerability Database results."""
        try:
            vulns = content.get("vulnerabilities", [])
            if vulns:
                self.console.print("|")
                self.console.print(f"|[green]+ National Vulnearbility Database Result[/green]")
                self.console.print("|-----------------------------------------------")

                predata = []
                for data in vulns:
                    id_ = data["cve"]["id"]
                    desc = data["cve"]["descriptions"][0]["value"]
                    self.console.print(f"|[blue]-[/blue] ID : {id_}")
                    self.console.print(f"|[blue]-[/blue] Description : {desc}")
                    self.console.print(
                        f"|[blue]-[/blue] Link : https://nvd.nist.gov/vuln/detail/{id_}"
                    )
                    self.console.print("|")
                    self.console.print("|")

                    predata.append(
                        {"title": id_, "description": desc, "link": f"https://nvd.nist.gov/vuln/detail/{id_}"}
                    )
                self.console.print(
                    f"|[blue]-[/blue] Total Result : [green]{len(vulns)}[/green] CVEs Found!"
                )
                self.data.append({"nvddb": predata})
        except Exception:
            self.console.print("|")
            self.console.print("|[red]- No result in National Vulnearbility Database![/red]")

    def cvesearch(self, content :dict):
        """Placeholder for a POC search (original code)."""
        try:
            if content:
                self.console.print(f"|[green]+ POC Finder[/green]")
                self.console.print("======")
                self.console.print(content)
        except Exception:
            self.console.print("Unable to find POC from Tricktest CVE database.")

    # --------------------------------------------------------------------------- #
    #                           Data export helpers                             #
    # --------------------------------------------------------------------------- #
    def outJson(self, location: str = ""):
        self._gen_out_dir(location)
        report = json.dumps(self.data, indent=4)
        open(f"{location}/report.json", "w").write(report)

    def outYaml(self, file: str, location: str = ""):
        """Export data to YAML."""
        report = pyaml.dump(self.data, indent=4, sort_keys=False)
        with open(f"{file}report.yaml", "w", encoding="utf-8") as f:
            f.write(report)

    # --------------------------------------------------------------------------- #
    #                             Utility helpers (re‑worked)                    #
    # --------------------------------------------------------------------------- #
    def _gen_out_dir(self, location: str):
        """Create output directory if it doesn't exist."""
        if not os.path.isdir(location):
            os.makedirs(location, exist_ok=True)
