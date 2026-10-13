#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[ERR] requests tidak terinstall.")
    sys.exit(1)

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError:
    print("[ERR] colorama tidak terinstall.")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

try:
    import pyfiglet
    PYFIGLET_AVAILABLE = True
except ImportError:
    PYFIGLET_AVAILABLE = False

from scanner import (
    Recon, Crawler, SensitiveScanner, VulnScanner, TemplateEngine,
    SENSITIVE_PATHS, CVE_TEMPLATES, USER_AGENTS
)
from exploiter import AutoExploiter

VERSION = "2.1.0"
AUTHOR = "ENI"

CYAN = Fore.CYAN
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
RED = Fore.RED
MAGENTA = Fore.MAGENTA
RESET = Style.RESET_ALL
BOLD = Style.BRIGHT


class Reporter:

    def __init__(self, output_dir, domain, base_url):
        self.output_dir = output_dir
        self.domain = domain
        self.base_url = base_url
        os.makedirs(output_dir, exist_ok=True)

    def write_txt(self, filename, lines):
        path = os.path.join(self.output_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(str(l) for l in lines))
        return path

    def save_subs(self, subs):
        return self.write_txt("subs.txt", subs)

    def save_alive(self, alive):
        return self.write_txt("alive.txt", alive)

    def save_urls(self, urls):
        return self.write_txt("urls.txt", urls)

    def save_sensitive(self, findings):
        lines = []
        for f in findings:
            lines.append(
                f"[{f.get('severity','INFO')}] {f.get('url','')} "
                f"| status={f.get('status_code','')} "
                f"| len={f.get('content_length','')} "
                f"| type={f.get('content_type','')} "
                f"| {f.get('note','')}"
            )
            if f.get("snippet"):
                lines.append(f"    snippet: {f['snippet'][:200]}")
        return self.write_txt("sensitive.txt", lines)

    def save_js_findings(self, findings):
        lines = []
        for f in findings:
            lines.append(
                f"[{f.get('type','JS')}] {f.get('value','')} "
                f"| source={f.get('source','')}"
            )
        return self.write_txt("js-findings.txt", lines)

    def save_vulns(self, vulns):
        lines = []
        for v in vulns:
            cve = v.get("cve_id", "")
            cve_str = f" ({cve})" if cve else ""
            lines.append(
                f"[{v.get('severity','INFO')}] {v.get('type','')}"
                f"{cve_str} | {v.get('url','')} "
                f"| param={v.get('param','')} "
                f"| payload={v.get('payload','')}"
            )
            if v.get("evidence"):
                lines.append(f"    evidence: {v['evidence'][:300]}")
        return self.write_txt("vulns.txt", lines)

    def save_session(self, data):
        path = os.path.join(self.output_dir, "session.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        return path

    def generate_html(self, data):
        html = self._build_html(data)
        path = os.path.join(self.output_dir, "report.html")
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        return path

    def _build_html(self, data):
        def esc(s):
            return (str(s).replace("&", "&amp;").replace("<", "&lt;")
                    .replace(">", "&gt;").replace('"', "&quot;"))

        domain = data.get("domain", "")
        base_url = data.get("base_url", "")
        start = data.get("start_time", "")
        mode = data.get("mode", "")
        subs = data.get("subdomains", [])
        alive = data.get("alive_hosts", [])
        urls = data.get("urls", [])
        sensitive = data.get("sensitive", [])
        js_findings = data.get("js_findings", [])
        vulns = data.get("vulns", [])
        exploits = data.get("exploits", [])

        rows_sensitive = "".join(
            f"<tr><td class='sev-{esc(f.get('severity',''))}'>"
            f"{esc(f.get('severity',''))}</td>"
            f"<td><a href='{esc(f.get('url',''))}'>{esc(f.get('url',''))}</a></td>"
            f"<td>{esc(f.get('status_code',''))}</td>"
            f"<td>{esc(f.get('content_length',''))}</td>"
            f"<td>{esc(f.get('note',''))}</td></tr>"
            for f in sensitive
        ) or "<tr><td colspan='5'>Tidak ada</td></tr>"

        rows_js = "".join(
            f"<tr><td>{esc(f.get('type',''))}</td>"
            f"<td>{esc(f.get('value','')[:300])}</td>"
            f"<td>{esc(f.get('source',''))}</td></tr>"
            for f in js_findings
        ) or "<tr><td colspan='3'>Tidak ada</td></tr>"

        rows_vulns = "".join(
            f"<tr><td class='sev-{esc(v.get('severity',''))}'>"
            f"{esc(v.get('severity',''))}</td>"
            f"<td>{esc(v.get('type',''))}</td>"
            f"<td>{esc(v.get('cve_id',''))}</td>"
            f"<td><a href='{esc(v.get('url',''))}'>{esc(v.get('url',''))}</a></td>"
            f"<td>{esc(v.get('param',''))}</td>"
            f"<td>{esc(v.get('payload','')[:200])}</td></tr>"
            for v in vulns
        ) or "<tr><td colspan='6'>Tidak ada</td></tr>"

        rows_exploits = "".join(
            f"<tr><td>{esc(e.get('cve_id',''))}</td>"
            f"<td>{esc(e.get('target',''))}</td>"
            f"<td>{esc(e.get('status',''))}</td>"
            f"<td>{esc(e.get('output','')[:300])}</td></tr>"
            for e in exploits
        ) or "<tr><td colspan='4'>Tidak ada</td></tr>"

        return f"""<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<title>deepcrawl Report - {esc(domain)}</title>
<style>
:root {{
  --bg: #0d1117;
  --bg2: #161b22;
  --border: #30363d;
  --text: #c9d1d9;
  --cyan: #58a6ff;
  --green: #3fb950;
  --red: #f85149;
  --yellow: #d29922;
  --magenta: #bc8cff;
}}
* {{ box-sizing: border-box; }}
body {{
  background: var(--bg); color: var(--text);
  font-family: 'Segoe UI', system-ui, sans-serif;
  margin: 0; padding: 24px;
}}
h1, h2 {{ color: var(--cyan); border-bottom: 1px solid var(--border); padding-bottom: 8px; }}
h1 {{ font-size: 1.6rem; }}
h2 {{ font-size: 1.2rem; margin-top: 32px; }}
.meta {{
  background: var(--bg2); border: 1px solid var(--border);
  border-radius: 8px; padding: 16px; margin-bottom: 24px;
}}
.meta span {{ display: inline-block; margin-right: 24px; }}
.meta b {{ color: var(--cyan); }}
table {{
  width: 100%; border-collapse: collapse; margin-top: 12px;
  background: var(--bg2); border-radius: 8px; overflow: hidden;
}}
th, td {{
  padding: 10px 12px; text-align: left;
  border-bottom: 1px solid var(--border); font-size: 0.85rem;
}}
th {{ background: #1f2937; color: var(--cyan); font-weight: 600; }}
tr:hover {{ background: #1c2128; }}
a {{ color: var(--cyan); text-decoration: none; word-break: break-all; }}
a:hover {{ text-decoration: underline; }}
.sev-CRITICAL {{ color: var(--red); font-weight: bold; }}
.sev-HIGH {{ color: var(--yellow); font-weight: bold; }}
.sev-MEDIUM {{ color: var(--magenta); }}
.sev-LOW {{ color: var(--green); }}
.footer {{ margin-top: 40px; color: #6e7681; font-size: 0.75rem; text-align: center; }}
</style>
</head>
<body>
<h1>deepcrawl Report</h1>
<div class="meta">
  <span><b>Domain:</b> {esc(domain)}</span>
  <span><b>Base URL:</b> {esc(base_url)}</span>
  <span><b>Mode:</b> {esc(mode)}</span>
  <span><b>Start:</b> {esc(start)}</span>
</div>
<h2>Ringkasan</h2>
<div class="meta">
  <span><b>Subdomain:</b> {len(subs)}</span>
  <span><b>Host Alive:</b> {len(alive)}</span>
  <span><b>URL:</b> {len(urls)}</span>
  <span><b>Sensitive:</b> {len(sensitive)}</span>
  <span><b>JS:</b> {len(js_findings)}</span>
  <span><b>Vulns:</b> {len(vulns)}</span>
  <span><b>Exploits:</b> {len(exploits)}</span>
</div>
<h2>Sensitive Files</h2>
<table>
<tr><th>Severity</th><th>URL</th><th>Status</th><th>Length</th><th>Note</th></tr>
{rows_sensitive}
</table>
<h2>JS Findings</h2>
<table>
<tr><th>Type</th><th>Value</th><th>Source</th></tr>
{rows_js}
</table>
<h2>Vulnerabilities</h2>
<table>
<tr><th>Severity</th><th>Type</th><th>CVE</th><th>URL</th><th>Param</th><th>Payload</th></tr>
{rows_vulns}
</table>
<h2>Auto Exploit Results</h2>
<table>
<tr><th>CVE</th><th>Target</th><th>Status</th><th>Output</th></tr>
{rows_exploits}
</table>
<div class="footer">deepcrawl v{VERSION} by {AUTHOR} &mdash; {datetime.now().year}</div>
</body>
</html>"""


class DeepCrawl:

    def __init__(self, raw_input, depth=4, threads=20, rate=10,
                 output_dir=None, no_recon=False, only_vuln=False,
                 auto_exploit=False, force_mode=None):
        self.raw_input = raw_input.strip()
        self.depth = depth
        self.threads = threads
        self.rate = rate
        self.no_recon = no_recon
        self.only_vuln = only_vuln
        self.auto_exploit = auto_exploit

        self.mode = force_mode or self._detect_input_mode(self.raw_input)

        self.has_protocol = bool(re.match(r'^https?://', self.raw_input, re.I))
        stripped = re.sub(r'^https?://', '', self.raw_input).rstrip('/')
        self.domain = stripped.split('/')[0].split(':')[0].lower()

        self.base_url = None
        self.protocol = None
        self._detect_protocol()

        if output_dir:
            self.output_dir = output_dir
        else:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe = re.sub(r'[^a-zA-Z0-9_.-]', '_', self.domain)
            self.output_dir = os.path.join("results", f"{safe}_{ts}")
        os.makedirs(self.output_dir, exist_ok=True)

        self.subdomains = []
        self.alive_hosts = []
        self.crawled_urls = []
        self.sensitive_findings = []
        self.js_findings = []
        self.vulns = []
        self.exploits = []

        self.reporter = Reporter(self.output_dir, self.domain, self.base_url)
        self.console = Console() if RICH_AVAILABLE else None

    def _detect_input_mode(self, raw):
        if re.match(r'^https?://', raw, re.I):
            return "ROOT_ONLY"
        host = re.sub(r'^https?://', '', raw).rstrip('/').split('/')[0]
        host = host.split(':')[0]
        parts = [p for p in host.split('.') if p]
        if len(parts) <= 2:
            return "FULL_RECON"
        return "SUBDOMAIN_ONLY"

    def _detect_protocol(self):
        if self.has_protocol:
            self.base_url = self.raw_input.rstrip('/')
            self.protocol = self.base_url.split('://')[0]
            return
        for proto in ["https", "http"]:
            url = f"{proto}://{self.domain}"
            try:
                requests.get(url, timeout=8, verify=False, allow_redirects=True)
                self.base_url = url
                self.protocol = proto
                return
            except Exception:
                continue
        self.base_url = f"https://{self.domain}"
        self.protocol = "https"

    def _log(self, level, msg):
        colors = {"INFO": CYAN, "FOUND": GREEN, "VULN": RED,
                  "404": YELLOW, "WARN": YELLOW, "ERR": RED,
                  "CHAIN": MAGENTA, "EXPLOIT": RED}
        c = colors.get(level, RESET)
        print(f"{c}[{level}]{RESET}".ljust(18) + f" {msg}")

    def banner(self):
        if PYFIGLET_AVAILABLE:
            try:
                art = pyfiglet.figlet_format("deepcrawl", font="ansi_shadow")
                print(f"{CYAN}{art}{RESET}")
            except Exception:
                print(f"{CYAN}=== deepcrawl ==={RESET}")
        else:
            print(f"{CYAN}=== deepcrawl ==={RESET}")
        print(f"{CYAN}v{VERSION}{RESET} | author: {AUTHOR}")
        print(f"{CYAN}{'=' * 60}{RESET}\n")
        print(f"{YELLOW}[MODE]{RESET} {self.mode} | target: {self.base_url}\n")

    def run(self):
        self.banner()
        start = time.time()

        if self.mode == "SUBDOMAIN_ONLY":
            self._log("INFO", "Mode SUBDOMAIN_ONLY: analisis subdomain tunggal")
            self.subdomains = [self.domain]
            self.alive_hosts = [self.base_url]
            self.reporter.save_subs(self.subdomains)
            self.reporter.save_alive(self.alive_hosts)

        elif self.mode == "ROOT_ONLY":
            self._log("INFO", "Mode ROOT_ONLY: analisis root URL saja")
            self.subdomains = [self.domain]
            self.alive_hosts = [self.base_url]
            self.reporter.save_subs(self.subdomains)
            self.reporter.save_alive(self.alive_hosts)

        else:
            if self.no_recon:
                self._log("INFO", "FULL_RECON tapi --no-recon, skip subfinder")
                self.subdomains = [self.domain]
                self.alive_hosts = [self.base_url]
            else:
                self._log("CHAIN", "FULL_RECON: recon chain dimulai...")
                recon = Recon(self.domain, self.base_url, self.threads,
                              self.rate, self.output_dir)
                result = recon.run()
                self.subdomains = result.get("subdomains", [])
                self.alive_hosts = result.get("alive_hosts", [])
            self.reporter.save_subs(self.subdomains)
            self.reporter.save_alive(self.alive_hosts)

        crawl_depth = self.depth if self.mode == "FULL_RECON" else min(self.depth, 2)
        self._log("CHAIN", f"Crawling (depth={crawl_depth}, mode={self.mode})...")
        crawler = Crawler(self.base_url, self.domain, crawl_depth,
                          self.threads, self.rate, self.only_vuln)
        crawl_result = crawler.run()
        self.crawled_urls = crawl_result.get("urls", [])
        self.js_findings = crawl_result.get("js_findings", [])
        self.reporter.save_urls(self.crawled_urls)
        self.reporter.save_js_findings(self.js_findings)

        if not self.only_vuln:
            self._log("CHAIN", "Memindai file sensitif...")
            sens = SensitiveScanner(self.base_url, self.threads, self.rate)
            self.sensitive_findings = sens.run()
            self.reporter.save_sensitive(self.sensitive_findings)

        self._log("CHAIN", "Vulnerability checks...")
        vuln = VulnScanner(self.base_url, self.crawled_urls,
                           self.threads, self.rate)
        self.vulns = vuln.run()

        self._log("CHAIN", "CVE template matching...")
        tpl = TemplateEngine(self.base_url, self.threads, self.rate)
        tpl_vulns = tpl.run()
        self.vulns.extend(tpl_vulns)
        self.reporter.save_vulns(self.vulns)

        if self.auto_exploit:
            self._log("CHAIN", "Auto-exploit phase...")
            exploiter = AutoExploiter(self.base_url, self.vulns,
                                      self.threads, self.rate)
            self.exploits = exploiter.run()

        elapsed = time.time() - start
        session = {
            "domain": self.domain,
            "base_url": self.base_url,
            "mode": self.mode,
            "start_time": datetime.fromtimestamp(start).isoformat(),
            "elapsed_seconds": round(elapsed, 2),
            "subdomains": self.subdomains,
            "alive_hosts": self.alive_hosts,
            "urls": self.crawled_urls,
            "sensitive": self.sensitive_findings,
            "js_findings": self.js_findings,
            "vulns": self.vulns,
            "exploits": self.exploits,
        }
        self.reporter.save_session(session)
        html_path = self.reporter.generate_html(session)
        self._print_summary(elapsed, html_path)
        return session

    def _print_summary(self, elapsed, html_path):
        print(f"\n{CYAN}{'=' * 60}{RESET}")
        print(f"{BOLD}{CYAN}  RINGKASAN HASIL{RESET}")
        print(f"{CYAN}{'=' * 60}{RESET}")
        print(f"  {GREEN}Mode           :{RESET} {self.mode}")
        print(f"  {GREEN}Subdomain      :{RESET} {len(self.subdomains)}")
        print(f"  {GREEN}Host Alive     :{RESET} {len(self.alive_hosts)}")
        print(f"  {GREEN}URL Crawled    :{RESET} {len(self.crawled_urls)}")
        print(f"  {GREEN}Sensitive      :{RESET} {len(self.sensitive_findings)}")
        print(f"  {GREEN}JS Findings    :{RESET} {len(self.js_findings)}")
        print(f"  {RED}Vulnerabilities:{RESET} {len(self.vulns)}")
        print(f"  {RED}Exploits       :{RESET} {len(self.exploits)}")
        print(f"  {YELLOW}Waktu          :{RESET} {round(elapsed, 2)}s")
        print(f"  {CYAN}Output Dir     :{RESET} {self.output_dir}")
        print(f"  {CYAN}HTML Report    :{RESET} {html_path}")
        print(f"{CYAN}{'=' * 60}{RESET}\n")

        if RICH_AVAILABLE:
            table = Table(title="Findings", box=box.ROUNDED)
            table.add_column("Kategori", style="cyan")
            table.add_column("Jumlah", justify="right", style="green")
            table.add_row("Mode", self.mode)
            table.add_row("Subdomain", str(len(self.subdomains)))
            table.add_row("Host Alive", str(len(self.alive_hosts)))
            table.add_row("URL", str(len(self.crawled_urls)))
            table.add_row("Sensitive", str(len(self.sensitive_findings)))
            table.add_row("JS", str(len(self.js_findings)))
            table.add_row("Vulns", str(len(self.vulns)))
            table.add_row("Exploits", str(len(self.exploits)))
            self.console.print(table)


def parse_args():
    p = argparse.ArgumentParser(
        description="deepcrawl - Web Crawler & Vulnerability Discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("target", help="domain, subdomain, atau URL")
    p.add_argument("-d", "--depth", type=int, default=4)
    p.add_argument("-t", "--threads", type=int, default=20)
    p.add_argument("-r", "--rate", type=int, default=10)
    p.add_argument("-o", "--output", default=None)
    p.add_argument("--no-recon", action="store_true")
    p.add_argument("--only-vuln", action="store_true")
    p.add_argument("--auto-exploit", action="store_true")
    p.add_argument("--mode", choices=["SUBDOMAIN_ONLY", "FULL_RECON",
                                       "ROOT_ONLY"], default=None)
    return p.parse_args()


def main():
    args = parse_args()
    try:
        dc = DeepCrawl(
            raw_input=args.target,
            depth=args.depth,
            threads=args.threads,
            rate=args.rate,
            output_dir=args.output,
            no_recon=args.no_recon,
            only_vuln=args.only_vuln,
            auto_exploit=args.auto_exploit,
            force_mode=args.mode,
        )
        dc.run()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[WARN]{RESET} Dihentikan user.")
        sys.exit(0)
    except Exception as e:
        print(f"{RED}[ERR]{RESET} {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()