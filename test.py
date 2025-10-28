import os 
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path 
from rich.console import Console 
console = Console()
from poc import batch_from_file
from typing import Dict, List, Optional
file_path = sys.argv[1]
file_name = Path(file_path).stem
print (file_name)
temp_file = f"{file_name}_temp" # original nmap report, formatted
cve_file = f"{temp_file}_cve" #temporary cve file 
console.print("Running scan...")
#Run initial script 
def main():
    import subprocess
    #Report Creation======================================== 
    os.system(f"uv run nparse.py {file_path} >> {temp_file}")
    try:
        os.system(f"uv run main.py -nm {file_path} --all") # Finding services 
    except:
        console.print("Unable to run normal nmap scan for services")
    #Report Reviewing===============================================
    with open(f"{temp_file}", 'r') as file: #ensures file looks good 
        content = file.read()
        print(content)   
    
    subprocess.run(['grep', 'CVE', 'temp_file', '>>', 'cve_file'], capture_output=True, text=True)
    subprocess.run ("sed -i 's/CVE://g' cve_file", shell=True)
    """ 
    try:
        cve_output = os.system(f"uv run poc.py -f {cve_file} >> last_file")
    except:
                console.print("Fail")
    try:
            os.remove(temp_file)
    except:
            print("unable to remove")
    try:
        os.remove(cve_file)
    except: 
            print("can't remove")
    """
main()

"""
    if 'CVE' in f:
        from poc import fetch_poc
        for CVE in f:
            fetch_poc(CVE)
"""


    