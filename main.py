import os 
import sys
import pathlib
import argparse
import json
from modules import MsfModule
from modules import NvdDB
from modules import ExploitDB
from modules import CVESearch
from outparse import Output
from nparse2 import NmapParse

def main(args, keyword="", keyword_version=""):
    # Use the global Output instance instead of creating a new one
    global Output
    output = Output
    
    # ---- 1. Handle the 'all' flag ---------------------------------
    if args.all:
        args.exploitdb = True
        args.msfmodule = True
        args.cvesearch = True
        args.nvd = True

    # If we're processing Nmap data
    if args.nmap:
        nm_data = NmapParse.parse(pathlib.Path(args.nmap))
        if nm_data:
            for host in nm_data:
                for port in host["ports"]:
                    # Get service info
                    kw = port["product"] or port["service"]  # Use product if available, fallback to service
                    ver = port["version"] or ""
                    
                    # Look up each service
                    if kw:
                        output.start(kw, ver)
                        
                        # Do service-based lookups
                        if args.exploitdb or args.all:
                            results = ExploitDB.find(kw, ver)
                            output.exploitdb(results)
                            
                        if args.msfmodule or args.all:
                            results = MsfModule.find(kw, ver)
                            output.msfmodule(results)
                            
                        if args.nvd or args.all:
                            results = NvdDB.find(kw, ver)
                            output.nvddb(results)
                    
                    # Handle any CVEs found for the port
                    if "cve" in port and port["cve"]:
                        for cve_id in port["cve"]:
                            if args.cvesearch or args.all:
                                results = CVESearch.find(cve_id)
                                output.cvesearch(results)

    # Direct keyword/CVE search
    else:
        if keyword:
            output.start(keyword, keyword_version)
            
            # Check if it's a CVE ID
            if keyword.upper().startswith("CVE-"):
                if args.cvesearch or args.all:
                    results = CVESearch.find(keyword)
                    output.cvesearch(results)
            # Regular service/keyword search
            else:
                if args.exploitdb or args.all:
                    results = ExploitDB.find(keyword, keyword_version)
                    output.exploitdb(results)
                
                if args.msfmodule or args.all:
                    results = MsfModule.find(keyword, keyword_version)
                    output.msfmodule(results)
                
                if args.nvd or args.all:
                    results = NvdDB.find(keyword, keyword_version)
                    output.nvddb(results)

    # Handle output
    if args.output:
        if args.output_type == "json":
            output.outJson(args.output)
        elif args.output_type == "yaml":
            output.outYaml(args.output)
        else:
            output.outJson(args.output)

if __name__ == "__main__":
    #Initialize
    ExploitDB = ExploitDB()
    MsfModule = MsfModule()
    NvdDB = NvdDB()
    Output = Output()
    NmapParse = NmapParse()
    CVESearch = CVESearch()


    # print banner
    Output.banner()

    # Initialize the parser
    parser = argparse.ArgumentParser(description='Script to search for vulnerability and exploitation information.')

    # Add arguments
    parser.add_argument('-k','--keyword', type=str, help='Keyword to search')
    parser.add_argument('-kv','--keyword_version', type=str, help='Version number for the keyword search')
    parser.add_argument('-nm','--nmap', type=str, help='Identify via nmap output')
    parser.add_argument('--nvd', action='store_true', help='Use NVD as a source of information')
    parser.add_argument('--cvesearch', action='store_true', help='Use more refs as a source of information')
    parser.add_argument('--exploitdb', action='store_true', help='Use ExploitDB as a source of information')
    parser.add_argument('--all', action='store_true',help='Use both ExploitDB and Metasploit modules as sources')
    parser.add_argument('--msfmodule', action='store_true', help='Use metasploit module as a source of information')
    parser.add_argument('-o','--output', type=str, help='path to save the output')
    parser.add_argument('-ot','--output_type', type=str, help='output file type json and yaml')

    args = parser.parse_args()
    if args.nmap:
        
        nm_data = NmapParse.parse(pathlib.Path(args.nmap))
        if nm_data:
            for host in nm_data:
                for port in host["ports"]:
                    kw = port["service"]
                    ver = port["version"] or ""
                    main(args, kw, ver)
        else:
            print("[!] Error parsing the supplied Nmap file", file=sys.stderr)

    else:
        # Just a straight‑forward keyword search
        main(args, args.keyword or "", args.keyword_version or "")