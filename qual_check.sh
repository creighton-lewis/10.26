#!/bin/bash
set -x 
uv run main.py  -k CVE-2001-1002 --cvesearch 
uv run main.py  -k CVE-2001-1002 --nvd 
uv run main.py  -k apache --all 
uv run main.py  -k apache --msfmodule 
uv run main.py  -k apache --nvd
uv run main.py  -k apache --exploitdb 
uv run main.py  -k CVE-2001-1002 --exploitdb
uv run nparse.py xml_docs/xml3 
uv run nparse.py xml_docs/xml4
uv run poc.py -f
uv run main.py -kv apache_2.0 --exploitdb 
uv run main.py -kv apache_2.0 -o apache_2.0 
uv run main.py -k apache --msfmodule #fix msfmodule & formatting








