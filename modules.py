import json
import requests 
import os 
#Modules: These are the functions that help get the results we see 
class MsfModule():
    
    def __init__(self):
        pass

    def find(self, keyword = "", version=""):
        try:
            datamod = []
            keyword = f"{keyword.lower()} {version.lower()}"
            try:
                o = open("msf_copy.json", "r").read()
            except:
                print("error")
            try:
                o = open("files/msf_copy.json", "r").read()
            except:
                print("error")
            try:
                o = open("exploit_search/msf_copy.json", "r").read()
            except: 
                print("No msf_copy.json file found")
            modules = json.loads(o)
            result = [data for data in modules if keyword in data['title']]
            return result
        except:
            return False
        pass
        

class ExploitDB():
    def __init__(self):
        pass
    def find(self, keyword="", version=""):
        keyword = f"{keyword} {version}"
        headers={
            "X-Requested-With": "XMLHttpRequest"
        }
        resp = requests.get(f"https://www.exploit-db.com/?draw=5&columns%5B0%5D%5Bdata%5D=date_published&columns%5B0%5D%5Bname%5D=date_published&columns%5B0%5D%5Bsearchable%5D=true&columns%5B0%5D%5Borderable%5D=true&columns%5B0%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B0%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B1%5D%5Bdata%5D=download&columns%5B1%5D%5Bname%5D=download&columns%5B1%5D%5Bsearchable%5D=false&columns%5B1%5D%5Borderable%5D=false&columns%5B1%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B1%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B2%5D%5Bdata%5D=application_md5&columns%5B2%5D%5Bname%5D=application_md5&columns%5B2%5D%5Bsearchable%5D=true&columns%5B2%5D%5Borderable%5D=false&columns%5B2%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B2%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B3%5D%5Bdata%5D=verified&columns%5B3%5D%5Bname%5D=verified&columns%5B3%5D%5Bsearchable%5D=true&columns%5B3%5D%5Borderable%5D=false&columns%5B3%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B3%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B4%5D%5Bdata%5D=description&columns%5B4%5D%5Bname%5D=description&columns%5B4%5D%5Bsearchable%5D=true&columns%5B4%5D%5Borderable%5D=false&columns%5B4%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B4%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B5%5D%5Bdata%5D=type_id&columns%5B5%5D%5Bname%5D=type_id&columns%5B5%5D%5Bsearchable%5D=true&columns%5B5%5D%5Borderable%5D=false&columns%5B5%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B5%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B6%5D%5Bdata%5D=platform_id&columns%5B6%5D%5Bname%5D=platform_id&columns%5B6%5D%5Bsearchable%5D=true&columns%5B6%5D%5Borderable%5D=false&columns%5B6%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B6%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B7%5D%5Bdata%5D=author_id&columns%5B7%5D%5Bname%5D=author_id&columns%5B7%5D%5Bsearchable%5D=false&columns%5B7%5D%5Borderable%5D=false&columns%5B7%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B7%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B8%5D%5Bdata%5D=code&columns%5B8%5D%5Bname%5D=code.code&columns%5B8%5D%5Bsearchable%5D=true&columns%5B8%5D%5Borderable%5D=true&columns%5B8%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B8%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B9%5D%5Bdata%5D=id&columns%5B9%5D%5Bname%5D=id&columns%5B9%5D%5Bsearchable%5D=false&columns%5B9%5D%5Borderable%5D=true&columns%5B9%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B9%5D%5Bsearch%5D%5Bregex%5D=false&order%5B0%5D%5Bcolumn%5D=9&order%5B0%5D%5Bdir%5D=desc&start=0&length=10000&search%5Bvalue%5D={keyword}&search%5Bregex%5D=false&author=&port=&type=&tag=&platform=&_=1706673207285", headers=headers)
        if resp.status_code == 200:
            return resp.json()
        else:
            return False
        
class NvdDB():
    def __init__(self):
        pass

    def find(self, keyword = "", version = ""):
        resp = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={keyword}")
        if resp.status_code == 200:
            return resp.json()
        if resp.status_code != 200:
            return False
        keyword = f"{keyword} {version}"
        keyword = keyword.replace(" ", "%20")
        resp = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}")
        if resp.status_code == 200:
            return resp.json()
        if resp.status_code != 200:
            return False
       
"""
class CVESearch():
    def __init__(self):
        pass 
    def find(self, keyword = ""):
        # Handle direct CVE ID lookups
        if "CVE-" in keyword.upper():
            resp_text_new =[]
            cve_id = keyword.upper()
            if not cve_id.startswith("CVE-"):
                cve_id = f"CVE-{cve_id}"
            year = cve_id.split('-')[1]
            resp = requests.get(f"https://raw.githubusercontent.com/trickest/cve/refs/heads/main/{year}/{cve_id}.md")
            if resp.status_code == 200:
                return resp.text
            return False
"""
import re

class CVESearch():
    def __init__(self):
        pass 
    
    def find(self, keyword=""):
        # Handle direct CVE ID lookups
        if "CVE-" in keyword.upper():
            resp_text_new = []
            cve_id = keyword.upper()
            if not cve_id.startswith("CVE-"):
                cve_id = f"CVE-{cve_id}"
            year = cve_id.split('-')[1]
            resp = requests.get(f"https://raw.githubusercontent.com/trickest/cve/refs/heads/main/{year}/{cve_id}.md")
            
            if resp.status_code == 200:
                content = resp.text
                
                # Method 1: Remove lines containing img.shields
                lines = content.split('\n')
                filtered_lines = [line for line in lines if 'img.shields' not in line.lower()]
                
                # Method 2: Also remove markdown image syntax with shields URLs
                # Pattern: ![alt text](url) or ![](url)
                cleaned_content = '\n'.join(filtered_lines)
                cleaned_content = re.sub(r'!\[.*?\]\(.*?img\.shields.*?\)', '', cleaned_content, flags=re.IGNORECASE)
                
                # Clean up extra blank lines
                cleaned_content = re.sub(r'\n\s*\n\s*\n', '\n\n', cleaned_content)
                
                return cleaned_content.strip() if cleaned_content.strip() else False
            
            return False

        # Handle service-based lookups by querying NVD
        else:
            nvd = NvdDB()
            results = nvd.find(keyword)
            if results and 'vulnerabilities' in results:
                cve_list = []
                for vuln in results['vulnerabilities']:
                    if 'cve' in vuln:
                        cve_id = vuln['cve']['id']
                        # For each CVE found, try to get POC info
                        poc_info = self.find(cve_id)
                        if poc_info:
                            cve_list.append({
                                'cve_id': cve_id,
                                'poc': poc_info
                            })
                return {'cves': cve_list} if cve_list else False
            return False

