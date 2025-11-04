import requests #type:ignore
import json 
from rich.console import Console
import requests #type:ignore
console = Console()
import argparse
import requests
from rich.console import Console

def fetch_poc(cve):
    cve = cve.upper()
    if not cve.startswith("CVE-"):
        cve = f"CVE-{cve}"
    year = cve.split("-")[1]
    url  = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"

    r    = requests.get(url, timeout=10)
    if r.status_code == 200:
        console.print(f"[bold green]NVDB URL found for {cve}[/bold green]")
        console.print(r.text)
        if r.text.strip() == "*No PoCs":
            console.print("[bold yellow]No POCs available[/bold yellow]")
    elif r.status_code == 404:
        console.print(f"[red]POC not found for {cve}[/red]")
    else:
        console.print(f"[red]Error fetching {cve}[/red]")

# --------------------------------------------------------------------------- #
# 2️⃣  Batch logic – read CVEs from a file
# --------------------------------------------------------------------------- #
def batch_from_file(path):
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            cve = line.strip()
            if not cve:
                continue
            fetch_poc(cve)

# --------------------------------------------------------------------------- #
# 3️⃣  CLI
# --------------------------------------------------------------------------- #
def main() -> None:
    parser = argparse.ArgumentParser(description="Find NVDB CVE POCs")
    parser.add_argument(
        "-f", "--file", metavar="FILE",
        help="Read a list of CVEs (one per line) from FILE"
    )
    parser.add_argument(
        "-s", "--single", metavar="CVE",
        help="Search a single CVE ID"
    )
    args = parser.parse_args()

    if args.file:
        batch_from_file(args.file)
    elif args.single:
        fetch_poc(args.single)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
