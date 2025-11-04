#!/usr/bin/env python3
"""
tools/diff_inventory.py

Compara dois ficheiros inventory.json (old vs new) e lista diferenças:
- hosts novos/removidos
- portas novas/removidas por host
- mudanças de serviço/version/CVEs em portas existentes

Usage:
  python3 tools/diff_inventory.py old_inventory.json new_inventory.json
"""
import json
import sys

def load_inv(path):
    with open(path) as f:
        return json.load(f).get("hosts", {})

def summarize_ports(host_data):
    # devolve dict port -> (service, version, sorted(cves))
    out = {}
    for p in host_data.get("ports", []):
        port = str(p.get("port"))
        svc = p.get("service","")
        ver = p.get("version","")
        cves = sorted(p.get("cves", []))
        out[port] = (svc, ver, cves)
    return out

def diff(old_path, new_path):
    old = load_inv(old_path) if old_path else {}
    new = load_inv(new_path)

    old_ips = set(old.keys())
    new_ips = set(new.keys())

    added_hosts = new_ips - old_ips
    removed_hosts = old_ips - new_ips
    common = old_ips & new_ips

    if added_hosts:
        print("[+] New hosts:")
        for ip in sorted(added_hosts):
            print(f"    + {ip}")
    if removed_hosts:
        print("[-] Removed hosts:")
        for ip in sorted(removed_hosts):
            print(f"    - {ip}")

    for ip in sorted(common):
        o_ports = summarize_ports(old[ip])
        n_ports = summarize_ports(new[ip])

        o_set = set(o_ports.keys())
        n_set = set(n_ports.keys())

        new_ports = n_set - o_set
        closed_ports = o_set - n_set
        if new_ports or closed_ports:
            print(f"[*] Host {ip}:")
            for p in sorted(new_ports, key=lambda x:int(x) if x.isdigit() else x):
                svc, ver, cves = n_ports[p]
                print(f"    [+] Port opened: {p} -> {svc} {ver} CVEs:{','.join(cves) if cves else '-'}")
            for p in sorted(closed_ports, key=lambda x:int(x) if x.isdigit() else x):
                svc, ver, cves = o_ports[p]
                print(f"    [-] Port closed: {p} -> {svc} {ver} CVEs:{','.join(cves) if cves else '-'}")

        # check for service/version/CVE changes on common ports
        common_ports = o_set & n_set
        for p in sorted(common_ports, key=lambda x:int(x) if x.isdigit() else x):
            o_svc, o_ver, o_cves = o_ports[p]
            n_svc, n_ver, n_cves = n_ports[p]
            changes = []
            if o_svc != n_svc:
                changes.append(f"service: '{o_svc}' -> '{n_svc}'")
            if o_ver != n_ver:
                changes.append(f"version: '{o_ver}' -> '{n_ver}'")
            if sorted(o_cves) != sorted(n_cves):
                added = set(n_cves) - set(o_cves)
                removed = set(o_cves) - set(n_cves)
                parts = []
                if added: parts.append("added CVEs: " + ",".join(sorted(added)))
                if removed: parts.append("removed CVEs: " + ",".join(sorted(removed)))
                changes.append("; ".join(parts))
            if changes:
                print(f"    [~] Host {ip} port {p} changes: " + " | ".join(changes))

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 tools/diff_inventory.py old_inventory.json new_inventory.json")
        sys.exit(2)
    old, new = sys.argv[1], sys.argv[2]
    diff(old, new)

if __name__ == "__main__":
    main()
