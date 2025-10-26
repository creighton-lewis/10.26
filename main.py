"""
from files.exploitr.module_msf import MsfModule
from files.exploitr.module_msf import NvdDB
from files.exploitr.module_msf import ExploitDB
"""
import os 
import sys
import pathlib
import argparse
import json
from exploit_search.modules import MsfModule
from exploit_search.modules import NvdDB
from exploit_search.modules import ExploitDB
from exploit_search.modules import CVESearch
from common.out_parse import Output
from nmap_scan.nparse import NmapParse
#from common.nmap_parse_copy import NmapParse
#from common.nmap_parse_copy import NmapParse

import argparse
import json

def main(args, keyword="", keyword_version=""):
    # ---- 1. Handle the 'all' flag ---------------------------------
    if args.all:
        args.exploitdb = True
        args.msfmodule = True
        args.cvesearch = True
        args.nvd = True        # now the following blocks will run

    # ---- 2. Execute each source -----------------------------------
    if args.exploitdb:
        getnvd = (ExploitDB.find(keyword, keyword_version)
                  if keyword_version else
                  ExploitDB.find(keyword))
        Output.exploitdb(getnvd)

    if args.msfmodule:
        getnvd = (MsfModule.find(keyword, keyword_version)
                  if keyword_version else
                  MsfModule.find(keyword))
        Output.msfmodule(getnvd)

    if args.nvd:
        getnvd = (NvdDB.find(keyword, keyword_version)
                  if keyword_version else
                  NvdDB.find(keyword))
        Output.nvddb(getnvd)
    
    if args.cvesearch:
        from poc import fetch_poc
        getcve = (CVESearch.find(keyword)
                  if keyword else
                  CVESearch.find(keyword))
        Output.cvesearch(getcve)
      
   
    
    if args.output:
        
        if args.output_type  == "json":
            Output.outJson(args.output)
        elif args.output_type == "yaml":
            Output.outYaml(args.output)
        else:
            Output.outJson(args.output)
            Output.outHtml(args.output)
   

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
    parser.add_argument('-kv','--keyword_version', type=str, help='File name or path to save the output')
    parser.add_argument('-nm','--nmap', type=str, help='Identify via nmap output')
    parser.add_argument('--nvd', action='store_true', help='Use NVD as a source of information')
    parser.add_argument('--cvesearch', action='store_true', help='Use more refs as a source of information')
    parser.add_argument('--exploitdb', action='store_true', help='Use ExploitDB as a source of information')
    parser.add_argument('--all', action='store_true',help='Use both ExploitDB and Metasploit modules as sources')
    parser.add_argument('--msfmodule', action='store_true', help='Use metasploit module as a source of information')
    parser.add_argument('-o','--output', type=str, help='path to save the output')
    parser.add_argument('-ot','--output_type', type=str, help='output file type json and html')

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
"""
    if args.nmap:
        nmparse = NmapParse.parse(args.nmap)
        if nmparse:
            for service in nmparse:
                main(args, service['service'], service['version'])
        else:
           print("[!] Only Supported for single host portscan result")
    else:
        keyword = args.keyword
        keyword_version = args.keyword_version
        main(args, keyword , keyword_version)
"""