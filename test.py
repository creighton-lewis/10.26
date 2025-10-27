import os 
import sys
import time
from rich.console import Console 
console = Console()
from poc import batch_from_file
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional
file_name = "xml3"
temp_file = f"{file_name}_temp"
cve_file = f"{file_name}_temp_cve"
console.print("Running scan...")
#Run initial script 
def main():
    os.system(f"uv run nparse.py xml_docs/{file_name} >> {temp_file}")
    #os.system(f" sed -E 's/CVE://' {temp_file}")
    console.print("Here's the scan", style = "bold cyan")
    with open(f"{temp_file}", 'r') as file:
        content = file.read()
        print(content)   
    result = os.system(f"grep 'CVE' {temp_file} >> {cve_file}")
    os.system(f"sed -E 's/CVE://' {cve_file} ")
try:
        cve_output = batch_from_file(f"{cve_file}")
except:
        console.print("Fail")
try:
            cve_output = os.system(f"uv run poc.py -f {cve_file} >> last_file")
except:
            console.print("Fail")
main()

"""
    if 'CVE' in f:
        from poc import fetch_poc
        for CVE in f:
            fetch_poc(CVE)
"""


    