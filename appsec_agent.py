import subprocess
import re
import json
import requests
from colorama import Fore, Style, init
from openai import OpenAI

client = OpenAI()

# ------- -1) Print Banner -----------

ASCII_NEONVULN = r"""
███╗   ██╗ ███████╗  ██████╗  ███╗   ██╗     ██╗   ██╗ ██╗   ██╗ ██╗      ███╗   ██╗
████╗  ██║ ██╔════╝ ██╔═══██╗ █████╗  ██║     ██║   ██║ ██║   ██║ ██║      ████╗  ██║
██╔██╗ ██║ █████╗   ██║   ██║ ██╔██╗ ██║     ██║   ██║ ██║   ██║ ██║      ██╔██╗ ██║
██║╚██╗██║ ██╔══╝   ██║   ██║ ██║╚██╗██║     ╚██╗ ██╔╝ ██║   ██║ ██║      ██║╚██╗██║
██║ ╚████║ ███████╗ ╚██████╔╝ ██║ ╚████║      ╚████╔╝  ╚██████╔╝ ███████╗ ██║ ╚████║
╚═╝  ╚═══╝ ╚══════╝  ╚═════╝  ╚═╝  ╚═══╝       ╚═══╝    ╚═════╝  ╚══════╝ ╚═╝  ╚═══╝
"""

def print_banner():
    width = 94

    # Top border
    print(Fore.LIGHTMAGENTA_EX + "╔" + "─" * width + "╗")

    for line in ASCII_NEONVULN.strip("\n").split("\n"):
        padding = width - len(line)
        print("│ " + Fore.LIGHTMAGENTA_EX + line + " " * padding + "│")

    # Spacer
    print("│" + " " * width + "│")

    subtitle = "✦  N  E  O  N  V  U  L  N  —  ネオン脆弱性スキャナー  ✦"
    pad = (width - len(subtitle)) // 2
    print("│" + " " * pad + Fore.CYAN + subtitle + Fore.LIGHTMAGENTA_EX +
          " " * (width - len(subtitle) - pad) + "│")

    # Spacer
    print("│" + " " * width + "│")

    # GitHub (exact screenshot formatting)
    gh = "github: @cyberbarbie"
    print("│   " + Fore.CYAN + gh + Fore.LIGHTMAGENTA_EX +
          " " * (width - len(gh) - 3) + "│")

    # Spacer
    print("│" + " " * width + "│")

    # Example (exact style from screenshot)
    print("│   " + Fore.CYAN + "Example:" + Fore.LIGHTMAGENTA_EX +
          " " * (width - len("Example:") - 3) + "│")

    cmd1 = "python appsec_agent.py"
    cmd2 = "# Then enter: vulnerable_target.com"

    print("│   " + Fore.CYAN + cmd1 + Fore.LIGHTMAGENTA_EX +
          " " * (width - len(cmd1) - 3) + "│")

    print("│   " + Fore.CYAN + cmd2 + Fore.LIGHTMAGENTA_EX +
          " " * (width - len(cmd2) - 3) + "│")

    # Bottom border
    print("╚" + "─" * width + "╝" + Style.RESET_ALL)



# --------- 0) Sanitize target ----------
def normalize_target(target: str) -> str:
    # remove https:// or http:// prefixes
    target = target.replace("https://", "").replace("http://", "")
    # remove trailing slashes
    return target.split("/")[0]

# --------- 1) Scope validation ----------
def validate_scope(target: str) -> None:
    # Simple guard rails. Expand however you want.
    dangerous = ["127.0.0.1", "localhost"]
    if target in dangerous:
        raise ValueError("Refusing to scan localhost in this demo. Use an authorized target.")
    if not re.match(r"^[a-zA-Z0-9\.\-:/]+$", target):
        raise ValueError("Target looks malformed. Use an IP/hostname only.")

# --------- 2) Nmap scan ----------
def run_nmap(target: str) -> str:
    print(f"[+] Running nmap on {target} ...")
    cmd = ["nmap", "-sV", "-Pn", "--top-ports", "100", target]
    return subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)

def parse_open_ports(nmap_output: str):
    ports = []
    for line in nmap_output.splitlines():
        # Example line: "80/tcp open  http    Apache httpd 2.4.57"
        m = re.match(r"(\d+)/tcp\s+open\s+(\S+)\s+(.*)", line)
        if m:
            port, service, version = m.groups()
            ports.append({"port": int(port), "service": service, "version": version.strip()})
    return ports

# --------- 3) Searchsploit ----------
def run_searchsploit(service: str, version: str) -> str:
    query = f"{service} {version}"
    print(f"[+] searchsploit: {query}")
    cmd = ["searchsploit", "--json", query]
    return subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)

def extract_cves(searchsploit_json: str):
    cves = set()
    try:
        data = json.loads(searchsploit_json)
        for item in data.get("RESULTS_EXPLOIT", []):
            text = (item.get("Title") or "") + " " + (item.get("Path") or "")
            for cve in re.findall(r"CVE-\d{4}-\d{4,7}", text):
                cves.add(cve)
    except json.JSONDecodeError:
        pass
    return sorted(cves)

# --------- 4) EPSS lookup ----------
def fetch_epss(cve_list):
    scores = {}
    for cve in cve_list:
        url = f"https://api.first.org/data/v1/epss?cve={cve}"
        r = requests.get(url, timeout=10)
        if r.ok:
            j = r.json()
            data = j.get("data", [])
            if data:
                scores[cve] = {
                    "epss": float(data[0]["epss"]),
                    "percentile": float(data[0]["percentile"]),
                }
    return scores

# --------- 5) LLM remediation ----------
def generate_remediation_report(target, ports, cves, epss_scores, raw_nmap):
    prompt = f"""
You are a senior Application Security Engineer.

Goal:
Write a clear, friendly, actionable remediation report for an authorized security assessment.

Target: {target}

Nmap output:
{raw_nmap}

Parsed open ports/services:
{json.dumps(ports, indent=2)}

CVEs inferred from searchsploit:
{json.dumps(cves, indent=2)}

EPSS scores:
{json.dumps(epss_scores, indent=2)}

Instructions:
1. Summarize the exposure (what is open, why it matters).
2. For EACH CVE, provide:
   - What it is (1-2 lines)
   - Risk & likelihood using EPSS
   - Concrete remediation steps
   - Verification steps
   - 2-3 references (NVD, vendor advisory, exploit-db ok)
3. If CVE data seems weak, say so explicitly.
Tone: helpful, AppSec, no fearmongering.
"""

    resp = client.responses.create(
        model="gpt-4.1-mini",
        input=prompt,
    )
    return resp.output_text

def main():
    target = input("Authorized target (IP/hostname): ").strip()
    validate_scope(target)

    nmap_out = run_nmap(target)
    ports = parse_open_ports(nmap_out)

    all_cves = []
    for p in ports:
        ss_out = run_searchsploit(p["service"], p["version"])
        cves = extract_cves(ss_out)
        all_cves.extend(cves)

    all_cves = sorted(set(all_cves))
    epss_scores = fetch_epss(all_cves)

    report = generate_remediation_report(target, ports, all_cves, epss_scores, nmap_out)

    print("\n" + "="*60)
    print(report)
    print("="*60)

if __name__ == "__main__":
    print_banner()
    main()

