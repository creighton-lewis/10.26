#!/bin/bash
set -x 
: ' 
uv run main.py  -k CVE-2001-1002 --cvesearch 
sleep 7s 
uv run main.py  -k CVE-2001-1002 --nvd 
sleep 7s
uv run main.py  -k apache --all 
sleep 7s
uv run main.py  -k apache --msfmodule 
sleep 7s
uv run main.py  -k apache --nvd
sleep 7s
uv run main.py  -k apache --exploitdb 
sleep 7s
uv run main.py  -k CVE-2001-1002 --exploitdb
sleep 7s
uv run nparse.py xml_docs/xml3 
sleep 7s
uv run nparse.py xml_docs/xml4
sleep 7s
uv run main.py -kv apache_2.0 --exploitdb 
sleep 7s
uv run main.py -kv apache_2.0 -o apache_2.0 
sleep 7s
uv run main.py -k apache --msfmodule 
sleep 7s
:'
uv run main.py -k apple -o apple -ot json
uv run main.py -k apple -o apple_1 -ot yaml





