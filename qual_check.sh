#!/bin/bash
set -x 
uv run main.py  -k CVE-2001-1002 --cvesearch 
sleep 10s 
uv run main.py  -k CVE-2001-1002 --nvd 
sleep 10s
uv run main.py  -k apache --all 
sleep 10s
uv run main.py  -k apache --msfmodule 
sleep 10s
uv run main.py  -k apache --nvd
sleep 10s
uv run main.py  -k apache --exploitdb 
sleep 10s
uv run main.py  -k CVE-2001-1002 --exploitdb
sleep 10s
uv run nparse.py xml_docs/xml3 
sleep 10s
uv run nparse.py xml_docs/xml4
sleep 10s
uv run main.py -kv apache_2.0 --exploitdb 
uv run main.py -kv apache_2.0 -o apache_2.0 
uv run main.py -k apache --msfmodule #fix msfmodule & formatting








