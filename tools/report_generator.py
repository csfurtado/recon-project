#!/usr/bin/env python3
"""
tools/report_generator.py

Gera out/report.md (e tenta gerar out/report.pdf usando 'pandoc' se disponível).

Uso:
  python3 tools/report_generator.py --outdir out --repo "Recon Automation" --author "Claudia S. Furtado"
"""
from datetime import datetime, timezone
import argparse
import json
import os
import shutil
import subprocess
import textwrap
import sys
import re

def load_inventory(inv_path):
    if not os.path.isfile(inv_path):
        return {}
    with open(inv_path, "r", encoding="utf-8") as f:
        try:
            return json.load(f).get("hosts", {})
        except Exception:
            return {}

def read_harvester_emails(harv_dir):
    emails = set()
    if not os.path.isdir(harv_dir):
        return []
    # try json outputs first
    for fn in os.listdir(harv_dir):
        if fn.endswith(".json"):
            p = os.path.join(harv_dir, fn)
            try:
                with open(p, encoding="utf-8") as f:
                    data = json.load(f)
                for e in data.get("emails", []):
                    emails.add(e)
            except Exception:
                pass
    # fallback: parse html files for emails (best-effort)
    email_re = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
    for fn in os.listdir(harv_dir):
        if fn.endswith(".html"):
            p = os.path.join(harv_dir, fn)
            try:
                with open(p, encoding="utf-8", errors="ignore") as f:
                    txt = f.read()
                for m in email_re.findall(txt):
                    emails.add(m)
            except Exception:
                pass
    return sorted(emails)

def top_hosts_summary(hosts, topn=10):
    items = []
    for ip, data in hosts.items():
        ports = [str(p.get("port")) for p in data.get("ports", [])]
        cves = []
        for p in data.get("ports", []):
            cves.extend(p.get("cves", []))
        items.append((ip, len(ports), ports, data.get("hostnames", []) or data.get("hostnames", []), sorted(set(cves))))
    items.sort(key=lambda x: x[1], reverse=True)
    return items[:topn]

def generate_markdown(outdir, repo, author):
    inv_path = os.path.join(outdir, "inventory.json")
    hosts = load_inventory(inv_path)
    total_hosts = len(hosts)
    total_ports = sum(len(data.get("ports", [])) for data in hosts.values())
    services = {}
    total_cves = 0
    for data in hosts.values():
        for p in data.get("ports", []):
            svc = p.get("service") or "unknown"
            services[svc] = services.get(svc, 0) + 1
            total_cves += len(p.get("cves", []))
    harv_dir = os.path.join(outdir, "harvester")
    emails = read_harvester_emails(harv_dir)

    md_lines = []
    md_lines.append(f"# Reconnaissance Automation Report\n")
    md_lines.append(f"**Project:** {repo}  ")
    md_lines.append(f"**Author:** {author}  ")
    md_lines.append(f"**Generated:** {datetime.now(timezone.utc).isoformat()}  \n")
    md_lines.append("---\n")

    md_lines.append("## Summary\n")
    md_lines.append(f"- Hosts detected: **{total_hosts}**")
    md_lines.append(f"- Total open ports: **{total_ports}**")
    md_lines.append(f"- Unique service fingerprints: **{len(services)}**")
    md_lines.append(f"- Total CVEs found (mapped/extracted): **{total_cves}**")
    md_lines.append("")

    md_lines.append("## Top services (by occurrences)\n")
    for svc, cnt in sorted(services.items(), key=lambda x: x[1], reverse=True)[:20]:
        md_lines.append(f"- {svc}: {cnt}")
    md_lines.append("")

    if emails:
        md_lines.append("## Emails found by theHarvester\n")
        for e in emails:
            md_lines.append(f"- {e}")
        md_lines.append("")

    md_lines.append("## Top hosts (by number of open ports)\n")
    md_lines.append("| IP | # ports | Ports | Hostnames | CVEs |")
    md_lines.append("|---|---:|---|---|---|")
    for ip, num, ports, hostnames, cves in top_hosts_summary(hosts, topn=20):
        hn = ",".join(hostnames) if hostnames else "-"
        md_lines.append(f"| {ip} | {num} | {','.join(ports) if ports else '-'} | {hn} | {','.join(cves) if cves else '-'} |")
    md_lines.append("")

    # embed graph image if exists (relative path)
    img_path = os.path.join(outdir, "inventory.png")
    if os.path.isfile(img_path):
        md_lines.append("## Graphical overview\n")
        # use relative path so pandoc can inline it
        rel = os.path.relpath(img_path, start=outdir)
        # but we are writing MD into outdir; use filename only
        md_lines.append(f"![inventory]({os.path.basename(img_path)})\n")
    else:
        md_lines.append("*(Image not found: out/inventory.png)*\n")

    md_lines.append("## Commands used\n")
    md_lines.append("```bash")
    md_lines.append("sudo masscan -iL targets.txt -p1-65535 --rate 500 -oJ out/masscan.json")
    md_lines.append("nmap -sC -sV -O -p- -oX out/nmap/<ip>.xml <ip>")
    md_lines.append("theHarvester -d example.lab -b all -f out/harvester/example_lab.html")
    md_lines.append("python3 tools/aggregate.py --masscan out/masscan.json --nmapdir out/nmap --outdir out")
    md_lines.append("```")
    md_lines.append("\n---\n")

    # include small excerpt of inventory
    try:
        excerpt = {}
        for i, (ip, data) in enumerate(hosts.items()):
            if i >= 10:
                break
            excerpt[ip] = data
        md_lines.append("## Inventory excerpt (top 10)\n")
        md_lines.append("```json")
        md_lines.append(json.dumps(excerpt, indent=2))
        md_lines.append("```")
    except Exception:
        pass

    return "\n".join(md_lines)

def write_files(outdir, md_text):
    os.makedirs(outdir, exist_ok=True)
    md_path = os.path.join(outdir, "report.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_text)
    print(f"[*] Report written: {md_path}")
    return md_path

def generate_pdf_with_pandoc(md_path, out_pdf_path):
    # Use system 'pandoc' to convert md -> pdf
    if not shutil.which("pandoc"):
        print("[!] pandoc not found in PATH. Skipping PDF generation.")
        return False
    # pandoc must be run from the outdir so relative image path works
    cwd = os.path.dirname(md_path)
    cmd = ["pandoc", os.path.basename(md_path), "-o", out_pdf_path, "--pdf-engine=xelatex"]
    try:
        print(f"[*] Running: {' '.join(cmd)}")
        subprocess.check_call(cmd, cwd=cwd)
        print(f"[*] PDF written: {out_pdf_path}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] pandoc failed: {e}")
        return False

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--outdir", default="out")
    p.add_argument("--repo", default="Recon Project")
    p.add_argument("--author", default=os.getenv("USER", "unknown"))
    args = p.parse_args()

    md_text = generate_markdown(args.outdir, args.repo, args.author)
    md_path = write_files(args.outdir, md_text)
    out_pdf = os.path.join(args.outdir, "report.pdf")

    # remove old artifacts
    try:
        if os.path.isfile(out_pdf):
            os.remove(out_pdf)
    except Exception:
        pass

    success = generate_pdf_with_pandoc(md_path, out_pdf)
    if not success:
        print("\n[!] PDF não gerado. Para gerar o PDF instala pandoc + texlive (ex.: Debian/Ubuntu/Kali):")
        print("    sudo apt update && sudo apt install -y pandoc texlive-xetex")
        print("Depois corre: pandoc out/report.md -o out/report.pdf --pdf-engine=xelatex\n")
    else:
        # Try to open the PDF (desktop)
        try:
            if sys.platform.startswith("linux"):
                subprocess.Popen(["xdg-open", out_pdf], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", out_pdf], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

if __name__ == "__main__":
    main()
