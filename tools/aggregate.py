#!/usr/bin/env python3
"""
tools/aggregate.py

Parse Masscan JSON and Nmap XML outputs, map service/version -> CVEs (local cache),
and emit out/inventory.json, out/inventory.csv and a Graphviz dot/png.

Usage:
  python3 tools/aggregate.py --masscan out/masscan.json --nmapdir out/nmap --outdir out
"""
import argparse
import csv
import glob
import json
import os
import re
import subprocess
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime, timezone

# ---------- helpers ----------
def load_cve_db(path="tools/cves.json"):
    if not os.path.isfile(path):
        print(f"[*] No local CVE DB found at {path} — continuing without CVE mapping.")
        return {}
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"[!] Failed to load CVE DB: {e}")
        return {}

def map_cves_local(service, version, cve_db):
    """
    Heuristic: match service name (case-insensitive substring) and version contains key.
    Returns list of CVE ids (unique).
    """
    if not service and not version:
        return []
    out = set()
    svc = (service or "").lower()
    ver = (version or "").lower()
    for name, versions in cve_db.items():
        if name.lower() in svc:
            for vkey, cves in versions.items():
                if str(vkey).lower() in ver:
                    for c in cves:
                        out.add(c)
    return sorted(out)

def ensure_outdir(outdir):
    os.makedirs(outdir, exist_ok=True)
    os.makedirs(os.path.join(outdir, "nmap"), exist_ok=True)
    os.makedirs(os.path.join(outdir, "harvester"), exist_ok=True)

# ---------- parse masscan ----------
def parse_masscan(masscan_path):
    hosts = defaultdict(lambda: {"ports": {}, "hostnames": []})
    if not masscan_path or not os.path.isfile(masscan_path):
        return hosts
    try:
        with open(masscan_path, "r") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[!] Could not parse masscan JSON ({masscan_path}): {e}")
        return hosts
    for entry in data:
        ip = entry.get("ip")
        if not ip:
            continue
        for p in entry.get("ports", []):
            port = p.get("port")
            if port is None:
                continue
            hosts[ip]["ports"][str(port)] = {
                "service": None,
                "version": None,
                "cves": [],
                "proto": p.get("proto","tcp")
            }
    print(f"[*] imported {len(hosts)} hosts from masscan")
    return hosts

# ---------- parse nmap xml ----------
def parse_nmap_dir(nmap_dir, hosts, cve_db):
    xml_files = glob.glob(os.path.join(nmap_dir, "*.xml"))
    parsed_files = 0
    for xf in xml_files:
        try:
            tree = ET.parse(xf)
            root = tree.getroot()
        except Exception as e:
            print(f"[!] Failed to parse Nmap XML {xf}: {e}")
            continue
        # Nmap XML has multiple <host>
        for h in root.findall("host"):
            # pick best address (prefer ipv4)
            ip = None
            for addr in h.findall("address"):
                atype = addr.attrib.get("addrtype","")
                cand = addr.attrib.get("addr")
                if not ip:
                    ip = cand
                # prefer ipv4 explicitly
                if atype == "ipv4":
                    ip = cand
                    break
            if not ip:
                continue
            _ = hosts[ip]  # create if missing
            # hostnames
            for hn in h.findall("hostnames/hostname"):
                name = hn.attrib.get("name")
                if name and name not in hosts[ip]["hostnames"]:
                    hosts[ip]["hostnames"].append(name)
            # collect hostscript outputs
            scripts_out = []
            for sc in h.findall("hostscript/script"):
                out = sc.attrib.get("output","")
                if out:
                    scripts_out.append(out)
            # parse ports
            for p in h.findall("ports/port"):
                portid = p.attrib.get("portid")
                proto = p.attrib.get("protocol")
                state_el = p.find("state")
                state = state_el.attrib.get("state") if state_el is not None else "unknown"
                if state != "open":
                    continue
                svc_el = p.find("service")
                svc_name = svc_el.attrib.get("name") if svc_el is not None else ""
                svc_prod = svc_el.attrib.get("product") if svc_el is not None else ""
                svc_ver = svc_el.attrib.get("version") if svc_el is not None else ""
                svc_extra = svc_el.attrib.get("extrainfo") if svc_el is not None else ""
                version_full = " ".join([s for s in [svc_prod, svc_ver, svc_extra] if s]).strip()
                # collect scripts outputs (port-level)
                scripts = []
                for sc in p.findall("script"):
                    out = sc.attrib.get("output","")
                    if out:
                        scripts.append(out)
                raw_text = "\n".join(scripts + scripts_out)
                # try extract CVEs by regex from scripts
                cve_re = re.compile(r"(CVE-\d{4}-\d{4,7})", re.IGNORECASE)
                found = sorted({m.upper() for m in cve_re.findall(raw_text)})
                # map local DB CVEs
                mapped = map_cves_local(svc_name or "", version_full or "", cve_db)
                cves = sorted(set(found + mapped))
                hosts[ip]["ports"].setdefault(str(portid), {
                    "service": svc_name or "",
                    "version": version_full or "",
                    "cves": cves,
                    "proto": proto or ""
                })
        parsed_files += 1
        print(f"[*] parsed {xf}")
    print(f"[*] parsed {parsed_files} xml files from {nmap_dir}")
    return hosts

# ---------- write outputs ----------
def write_inventory_json(hosts, outdir):
    inventory = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "hosts": {}
    }
    for ip, data in hosts.items():
        inventory["hosts"][ip] = {
            "ip": ip,
            "hostnames": sorted(data.get("hostnames", [])),
            "ports": []
        }
        for port, info in sorted(data.get("ports", {}).items(), key=lambda x: int(x[0]) if x[0].isdigit() else x[0]):
            inventory["hosts"][ip]["ports"].append({
                "port": int(port) if port.isdigit() else port,
                "protocol": info.get("proto", ""),
                "service": info.get("service", ""),
                "version": info.get("version", ""),
                "cves": info.get("cves", [])
            })
    outpath = os.path.join(outdir, "inventory.json")
    with open(outpath, "w") as f:
        json.dump(inventory, f, indent=2)
    print(f"[*] written {outpath}")
    return outpath

def write_inventory_csv(hosts, outdir):
    outpath = os.path.join(outdir, "inventory.csv")
    with open(outpath, "w", newline="") as csvf:
        w = csv.writer(csvf)
        w.writerow(["ip","port","protocol","state","service","version","cves","hostnames"])
        for ip, data in hosts.items():
            hostnames = ";".join(sorted(data.get("hostnames", [])))
            ports = data.get("ports", {})
            if not ports:
                w.writerow([ip,"", "","","","","", hostnames])
                continue
            for port, info in sorted(ports.items(), key=lambda x: int(x[0]) if x[0].isdigit() else x[0]):
                w.writerow([
                    ip,
                    port,
                    info.get("proto",""),
                    "open",
                    info.get("service",""),
                    info.get("version",""),
                    ";".join(info.get("cves", [])),
                    hostnames
                ])
    print(f"[*] written {outpath}")
    return outpath

def generate_graphviz(hosts, outdir):
    dotfile = os.path.join(outdir, "inventory.dot")
    pngfile = os.path.join(outdir, "inventory.png")
    lines = ["digraph Recon {", " rankdir=LR;", " node [shape=box];"]
    for ip, data in hosts.items():
        lines.append(f' "{ip}" [shape=ellipse, style=filled, fillcolor=lightblue];')
        for hn in data.get("hostnames", []):
            hn_s = hn.replace('"','\\"')
            lines.append(f' "{hn_s}" [shape=oval];')
            lines.append(f' "{hn_s}" -> "{ip}" [label="resolves"];')
        for port, info in data.get("ports", {}).items():
            svc = (info.get("service") or "service").strip()
            node = f"{svc}:{port}"
            node_s = node.replace('"','\\"')
            lines.append(f' "{ip}" -> "{node_s}" [label="port {port}"];')
            for cve in info.get("cves", []):
                cve_s = cve.replace('"','\\"')
                lines.append(f' "{node_s}" -> "{cve_s}" [color=red];')
    lines.append("}")
    with open(dotfile, "w") as f:
        f.write("\n".join(lines))
    print(f"[*] written {dotfile}")
    # try to render png if dot available
    try:
        subprocess.run(["dot", "-Tpng", dotfile, "-o", pngfile], check=True)
        print(f"[*] written {pngfile}")
    except FileNotFoundError:
        print("[!] Graphviz 'dot' not found; install graphviz to produce PNG from DOT.")
    except subprocess.CalledProcessError as e:
        print(f"[!] dot failed: {e}")

# ---------- main ----------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--masscan", default="out/masscan.json")
    parser.add_argument("--nmapdir", default="out/nmap")
    parser.add_argument("--outdir", default="out")
    args = parser.parse_args()

    ensure_outdir(args.outdir)
    cve_db = load_cve_db()
    hosts = parse_masscan(args.masscan)
    hosts = parse_nmap_dir(args.nmapdir, hosts, cve_db)
    write_inventory_json(hosts, args.outdir)
    write_inventory_csv(hosts, args.outdir)
    generate_graphviz(hosts, args.outdir)
    print("[*] aggregate completed.")

if __name__ == "__main__":
    main()
