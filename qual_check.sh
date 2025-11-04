#!/bin/bash
set -x 
uv run main.py -nm xmls/xml3 --all
sleep 7s
uv run main.py -nm xmls/xml4 --all
grep "CVE" xmls/xml5
uv run main.py -nm xmls/xml5 
uv run main.py -nm 
sleep 7s
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
clear
uv run main.py  -k CVE-2001-1002 --exploitdb
sleep 7s
uv run main.py -k apache -kv 2.0 --exploitdb 
sleep 7s
uv run main.py -kv apache_2.0 -o apache_2.0 
sleep 7s
uv run main.py -k apache --msfmodule 
sleep 7s
uv run main.py -k apple -o apple -ot json
uv run main.py -k apple -o apple_1 -ot yaml





