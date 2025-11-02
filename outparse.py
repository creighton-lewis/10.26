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
                             .d||b
                           .' TO|;
                          /  : TP._;
                         / _.;  :Tb|
                        /   /   ;j|j
                    _.-"       d||||
                  .' ..       d||||;
                 /  /P'      d||||P. |\^"l
              .'           'T|P^"""""  """
           ._.'      _.'                ;
       '-.-".-'-' ._.       _.-"    .-"
      '-." _____  ._              .-"
    -..g|||||||b.              .'
    ""^^T|||P^)            .(:
        _/  -  /.'         /:/;
     ._.'-''-'  ")/         /;/;
  '-.-"..--""   " /         /  ;
 .-" ..--""        -'          :
 ..--""--.-"         (\      .-(\
   ..--""              
     _.                      :
                             ;'- 
                            :\
 [blue]
 ______ _______ ______ 
|   __ \       |      |
|    __/   -   |   ---|
|___|  |_______|______|
 _______ _______ _______ _______ _____  
|   |   |       |   |   |    |  |     \ 
|       |   -   |   |   |       |  --  |
|___|___|_______|_______|__|____|_____/ 
[blue]
POC finder that uses metasploit, exploitdb, trickest CVE list,
and National Vulnerability database
    """
        self.console.print(ascii_art)

    def start(self, keyword: str = "", version: str = ""):
        self.console.print("|")
        self.console.print(f"|[yellow]> Starting with Keyword : {keyword} {version}[/yellow]")
        self.console.print("|----------------------------------------")

    # --------------------------------------------------------------------------- #
    #                            API result printing                           #
    # --------------------------------------------------------------------------- #
    def exploitdb(self, content):
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

    def msfmodule(self, content):
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
                    self.console.print(f"|[blue]-[/blue] Description : {data['description']}", justify="left")
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

    def cvesearch(self, content):
        """Show CVE search results with POC information."""
        try:
            if isinstance(content, str):
                # Direct POC result
                self.console.print("|")
                self.console.print(f"|[green]+ POC Information[/green]")
                self.console.print("|------------------")
                self.console.print(f"|[blue]-[/blue] {content}")
                self.console.print("|")
            elif isinstance(content, dict) and 'cves' in content:
                # Service-based search results
                self.console.print("|")
                self.console.print(f"|[green]+ CVE POC Results[/green]")
                self.console.print("|------------------")
                
                predata = []
                for cve in content['cves']:
                    self.console.print(f"|[blue]-[/blue] CVE ID: {cve['cve_id']}")
                    self.console.print(f"|[blue]-[/blue] POC Available: Yes")
                    self.console.print(f"|[blue]-[/blue] POC Details:")
                    self.console.print(cve['poc'])
                    self.console.print("|")
                    
                    predata.append({
                        'cve_id': cve['cve_id'],
                        'poc': cve['poc']
                    })
                
                self.console.print(
                    f"|[blue]-[/blue] Total Result: [green]{len(content['cves'])}[/green] POCs Found!"
                )
                self.data.append({"cvesearch": predata})
            else:
                self.console.print("|[red]- No POCs found![/red]")
        except Exception:
            self.console.print("|[red]- Internal Error - Could not process CVE search results![/red]")

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
