import os 
import sys
import time
from pathlib import Path 
from rich.console import Console 
console = Console()
from poc import batch_from_file
import xml.etree.ElementTree as ET
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
    os.system(f"uv run nparse.py {file_path} >> {temp_file}") #creates normal looking report 
    try:
        os.system(f"uv run main.py -nm {file_path} --all")
    except:
        console.print("Unable to run normal nmap scan for services")
    with open(f"{temp_file}", 'r') as file: #ensures file looks good 
        content = file.read()
        print(content)   
    #result = os.system(f"grep 'CVE' {temp_file} >> {cve_file}") #exports found cve's to a regular file 
    #os.remove(temp_file)
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


    