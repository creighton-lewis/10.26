from colorama import Fore, Back, Style
import re
import os
import json
import pyaml #type:ignore
class Output:
    def __init__(self):
        self.data = []
    
    def banner(self):
        ascii_art = f"""
_._     _,-'""`-._
(,-.`._,'(       |\`-/|
    `-.-' \ )-`( , {Fore.RED}o o{Fore.WHITE})
        `-    \`_`"'-
{Fore.RED}SiCat{Fore.WHITE} - The useful {Fore.RED}exploit{Fore.WHITE} finder
@justakazh (https://github.com/justakazh/sicat)

usage : vulny.py --help
        """
        print(ascii_art)

    def start(self,keyword = "", version = ""):
        print("|")
        print(f"|{Fore.YELLOW}> Starting with Keyword : {keyword} {version} {Fore.WHITE}")
        print("|----------------------------------------")

    def exploitdb(self, content):
        try:
            if len(content['data']) != 0:
                print("|")
                print(f"|{Fore.GREEN}+ Exploit-DB Result {Fore.WHITE}")
                print("|--------------------")

                predata = []
                for data in content['data']:
                    print(f"|{Fore.BLUE}-{Fore.WHITE} Title : {data['description'][1]}")
                    print(f"|{Fore.BLUE}-{Fore.WHITE} Type  : {data['type_id']}")
                    print(f"|{Fore.BLUE}-{Fore.WHITE} Link  : https://www.exploit-db.com/exploits/{data['description'][0]}")
                    print("|")
                    print("|")

                    predata.append({
                        "title" : data['description'][1],
                        "type" : data['type_id'],
                        "link" : f"https://www.exploit-db.com/exploits/{data['description'][0]}"
                    })
                print(f"|{Fore.BLUE}-{Fore.WHITE} Total Result : {Fore.GREEN}{len(content['data'])}{Fore.WHITE} Exploits Found!")
                self.data.append({"exploitdb" : predata})
            else:
                print(f"|{Fore.RED}- No result in ExploitDB!{Fore.WHITE}")
        except:
            print(f"|{Fore.RED}- Internal Error - No result in ExploitDB!{Fore.WHITE}")

  
    def msfmodule(self, content):
        try:
            if len(content) != 0:
                print("|")
                print(f"|{Fore.GREEN}+ Metasploit Module Result {Fore.WHITE}")
                print("|------------------------------")


                predata = []
                for data in content:
                    print(f"|{Fore.BLUE}-{Fore.WHITE} Title : {data['title'].capitalize()}")
                    print(f"|{Fore.BLUE}-{Fore.WHITE} Module : {data['module']}")
                    print(f"|{Fore.BLUE}-{Fore.WHITE} Link : {data['link']}")
                    print(f"|{Fore.BLUE}-{Fore.WHITE} Description : {data['description']}")
                    print("|")
                    print("|")

                    predata.append({
                        "title" : data['title'],
                        "module" : data['module'],
                        "link" : data['link']
                    })
                print(f"|{Fore.BLUE}-{Fore.WHITE} Total Result : {Fore.GREEN}{len(content)}{Fore.WHITE} Modules Found!")
                self.data.append({"msfmodule" : predata})
            else:
                print(f"|{Fore.RED}- No result in Metasploit Module!{Fore.WHITE}")
        except:
            print(f"|{Fore.RED}- Internal Error - No result in Metasploit Module!{Fore.WHITE} ")


    def nvddb(self, content):
        try:
            if len(content['vulnerabilities']) != 0:
                print("|")
                print(f"|{Fore.GREEN}+ National Vulnearbility Database Result {Fore.WHITE}")
                print("|-----------------------------------------------")

                predata = []
                for data in content['vulnerabilities']:
                    print(f"|{Fore.BLUE}-{Fore.WHITE} ID : {data['cve']['id']}")
                    print(f"|{Fore.BLUE}-{Fore.WHITE} Description : {data['cve']['descriptions'][0]['value']}")
                    print(f"|{Fore.BLUE}-{Fore.WHITE} Link : https://nvd.nist.gov/vuln/detail/{data['cve']['id']}")
                    print("|")
                    print("|")

                    predata.append({
                        "title" : data['cve']['id'],
                        "description" : data['cve']['descriptions'][0]['value'],
                        "link" : f"https://nvd.nist.gov/vuln/detail/{data['cve']['id']}"
                    })
                print(f"|{Fore.BLUE}-{Fore.WHITE} Total Result : {Fore.GREEN}{len(content)}{Fore.WHITE} CVEs Found!")
                self.data.append({"nvddb" : predata})
        except:
            print("|")
            print(f"|{Fore.RED}- No result in National Vulnearbility Database!{Fore.WHITE}")
        
            
    def cvesearch(self, content):
        try:
            if len(content) != 0:
                print(f"|{Fore.GREEN}+ POC Finder {Fore.WHITE}")

                predata = []
                print(f"======")
                print(content)
        except:
            print("Unable to find POC from Tricktest CVE database.")
    
    def outJson(self, location = ""):
        self.genOutDir(location)
        report = json.dumps(self.data, indent=4)
        open(f"{location}/report.json", "w").write(report)
    
    def outYaml(self, file, location=""):
        """Export data to YAML."""
        import pyaml
        yaml = pyaml
        self.genOutDir(location)
        report = yaml.dump(self.data, indent=4, sort_keys=False)
        with open (f"{file}report.yaml", "w", encoding="utf-8") as f:
        #with open(f"{location}/report.yaml", "w", encoding="utf-8") as f:
            f.write(report) 