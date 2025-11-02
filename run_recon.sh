#!/usr/bin/env bash
# run_recon.sh — Orquestrador com interface CLI, menu interactivo e suporte a --help
set -euo pipefail

# Defaults
OUTDIR="out"
MASSCAN_JSON="$OUTDIR/masscan.json"
NMAP_OUTDIR="$OUTDIR/nmap"
HARV_OUTDIR="$OUTDIR/harvester"
MASSCAN_RATE=500
MAX_NMAP_WORKERS=6
NMAP_EXTRA_ARGS="-sC -sV -O -p-"

# Usage/help text (used by -h and --help)
usage() {
  cat <<'EOF'
run_recon.sh — Orquestrador Recon Pipeline

Uso:
  sudo ./run_recon.sh [OPTIONS]

Se executado sem opções, abre um menu interactivo.

Options:
  -t, --targets "LIST"         Space-separated targets (IPs/CIDRs/hosts)
  -T, --targets-file FILE      File with targets (one per line)
  -d, --domains "LIST"         Space-separated domains for theHarvester
  -D, --domains-file FILE      File with domains (one per line)
  -r, --rate RATE              masscan rate (default 500)
  -w, --workers N              max parallel nmap workers (default 6)
  -h, --help                   Show this help and exit

Exemplos:
  # menu interactivo
  sudo ./run_recon.sh

  # modo CLI: targets inline + domains inline
  sudo ./run_recon.sh --targets "192.168.56.101 192.168.56.102" --domains "example.lab"

  # usar ficheiro de targets e ajustar rate/workers
  sudo ./run_recon.sh --targets-file targets.txt --rate 1000 --workers 8

Notas:
  - O script tenta usar targets.txt / domains.txt se não passares argumentos.
  - Só executa scans em alvos para os quais tens autorização.
EOF
}

# -----------------------
# Helpers
# -----------------------
ensure_dirs() { mkdir -p "$OUTDIR" "$NMAP_OUTDIR" "$HARV_OUTDIR"; }

run_masscan_from_file() {
  local file="$1"
  echo "[*] masscan (file) -> $file"
  sudo masscan -iL "$file" -p1-65535 --rate "$MASSCAN_RATE" -oJ "$MASSCAN_JSON"
}
run_masscan_from_targets() {
  local tgt="$1"
  echo "[*] masscan (targets) -> $tgt"
  sudo masscan $tgt -p1-65535 --rate "$MASSCAN_RATE" -oJ "$MASSCAN_JSON"
}

build_hosts_ports() {
  echo "[*] Construindo out/hosts_ports.txt a partir de $MASSCAN_JSON (se existir)"
  python3 - <<'PY' || true
import json,sys,os
fn="out/masscan.json"
if not os.path.isfile(fn):
    sys.exit(0)
with open(fn) as f:
    try:
        data=json.load(f)
    except:
        sys.exit(0)
from collections import defaultdict
byip=defaultdict(list)
for e in data:
    ip=e.get("ip")
    for p in e.get("ports",[]):
        byip[ip].append(str(p.get("port")))
with open("out/hosts_ports.txt","w") as f:
    for ip,ports in byip.items():
        f.write(f"{ip} {','.join(sorted(set(ports)))}\n")
print("[*] hosts_ports.txt gerado com",len(byip),"hosts")
PY
}

run_nmap_per_host() {
  echo "[*] Run Nmap per-host (confirm & fingerprint)"
  if [ -f out/hosts_ports.txt ] && [ -s out/hosts_ports.txt ]; then
    run_nmap() {
      ip="$1"
      ports="$2"
      outfile="$NMAP_OUTDIR/${ip}.xml"
      echo "[nmap] $ip -> $ports"
      sudo nmap $NMAP_EXTRA_ARGS -p "$ports" -oX "$outfile" "$ip" || echo "[!] nmap erro em $ip"
    }
    export -f run_nmap
    export NMAP_EXTRA_ARGS
    export NMAP_OUTDIR
    cat out/hosts_ports.txt | xargs -n2 -P "$MAX_NMAP_WORKERS" bash -c 'run_nmap "$0" "$1"'
    return 0
  else
    return 1
  fi
}

run_nmap_direct_targets() {
  local targets="$1"
  echo "[*] Running Nmap directly against targets: $targets"
  for t in $targets; do
    [ -z "$t" ] && continue
    outbase=$(echo "$t" | tr '/:' '_' )
    sudo nmap $NMAP_EXTRA_ARGS -p- -oX "$NMAP_OUTDIR/${outbase}.xml" "$t" || echo "[!] nmap erro $t"
  done
}

run_harvester_for_domains() {
  local domains="$1"
  echo "[*] Running theHarvester for domains: $domains"
  for d in $domains; do
    [ -z "$d" ] && continue
    outf="$HARV_OUTDIR/${d//./_}.html"
    echo "[harvester] $d -> $outf"
    theHarvester -d "$d" -b all -f "$outf" || echo "[!] harvester erro $d"
  done
}

compile_aggregate() {
  if [ ! -x tools/aggregate ]; then
    echo "[*] compilando tools/aggregate"
    (cd tools && go build -o aggregate aggregate.go)
  fi
}
run_aggregate() { compile_aggregate; tools/aggregate -masscan "$MASSCAN_JSON" -nmapdir "$NMAP_OUTDIR" -outdir "$OUTDIR"; }

# -----------------------
# Parse both short and long options using getopt
# -----------------------
if ! PARSED=$(getopt -o t:T:d:D:r:w:h --long targets:,targets-file:,domains:,domains-file:,rate:,workers:,help -- "$@"); then
  usage
fi
eval set -- "$PARSED"

TARGETS_CLI=""
TARGETS_FILE=""
DOMAINS_CLI=""
DOMAINS_FILE=""

while true; do
  case "$1" in
    -t|--targets) TARGETS_CLI="$2"; shift 2 ;;
    -T|--targets-file) TARGETS_FILE="$2"; shift 2 ;;
    -d|--domains) DOMAINS_CLI="$2"; shift 2 ;;
    -D|--domains-file) DOMAINS_FILE="$2"; shift 2 ;;
    -r|--rate) MASSCAN_RATE="$2"; shift 2 ;;
    -w|--workers) MAX_NMAP_WORKERS="$2"; shift 2 ;;
    -h|--help) usage; shift ;;
    --) shift; break ;;
    *) break ;;
  esac
done

# Assemble targets/domains
if [ -n "$TARGETS_CLI" ]; then
  TARGETS="$TARGETS_CLI"
elif [ -n "$TARGETS_FILE" ]; then
  if [ ! -f "$TARGETS_FILE" ]; then echo "Ficheiro targets não encontrado: $TARGETS_FILE"; exit 1; fi
  TARGETS="$(tr '\n' ' ' < "$TARGETS_FILE" | sed 's/[[:space:]]\+/ /g')"
elif [ -f "targets.txt" ]; then
  TARGETS="$(tr '\n' ' ' < targets.txt | sed 's/[[:space:]]\+/ /g')"
else
  TARGETS=""
fi

if [ -n "$DOMAINS_CLI" ]; then
  DOMAINS="$DOMAINS_CLI"
elif [ -n "$DOMAINS_FILE" ]; then
  if [ ! -f "$DOMAINS_FILE" ]; then echo "Ficheiro domains não encontrado: $DOMAINS_FILE"; exit 1; fi
  DOMAINS="$(tr '\n' ' ' < "$DOMAINS_FILE" | sed 's/[[:space:]]\+/ /g')"
elif [ -f "domains.txt" ]; then
  DOMAINS="$(tr '\n' ' ' < domains.txt | sed 's/[[:space:]]\+/ /g')"
else
  DOMAINS=""
fi

# If CLI provided targets/domains, run without menu
if [ -n "$TARGETS" ] || [ -n "$DOMAINS" ]; then
  ensure_dirs
  echo "[*] Targets: $TARGETS"
  echo "[*] Domains: $DOMAINS"
  echo "[*] Masscan rate: $MASSCAN_RATE"
  echo "[*] Max nmap workers: $MAX_NMAP_WORKERS"

  if [ -n "$TARGETS_FILE" ] || [ -f "targets.txt" ]; then
    if [ -n "$TARGETS_FILE" ]; then run_masscan_from_file "$TARGETS_FILE"
    else run_masscan_from_file "targets.txt"; fi
  else
    run_masscan_from_targets "$TARGETS"
  fi

  build_hosts_ports

  if run_nmap_per_host; then
    echo "[*] Nmap per-host concluído"
  else
    echo "[*] A usar Nmap direto aos targets"
    if [ -n "$TARGETS" ]; then run_nmap_direct_targets "$TARGETS"; fi
  fi

  if [ -n "$DOMAINS" ]; then run_harvester_for_domains "$DOMAINS"; fi

  run_aggregate
  echo "[*] Pipeline concluída. Outputs em $OUTDIR"
  exit 0
fi

# -----------------------
# Interactive menu (no CLI args)
# -----------------------
ensure_dirs
while true; do
  cat <<MENU

===========================================
 Recon Pipeline — Menu Interactivo
===========================================
Escolhe uma opção (tecla e Enter):

  1) Run FULL pipeline (Masscan -> Nmap -> theHarvester -> Aggregate)
  2) Run Masscan only
  3) Run Nmap only (confirm from masscan results or enter targets)
  4) Run theHarvester only (enter domains)
  5) Aggregate only (parse existing out/)
  6) Show last outputs (ls -R out/)
  7) Help (show usage)
  0) Exit
===========================================
MENU

  read -rp "Opção: " opt
  case "$opt" in
    1)
      read -rp "Targets (space-separated) or press Enter to use targets.txt: " t_in
      read -rp "Domains (space-separated) or press Enter to use domains.txt: " d_in
      read -rp "Masscan rate (default $MASSCAN_RATE): " rate_in
      read -rp "Max Nmap workers (default $MAX_NMAP_WORKERS): " w_in
      [ -n "$rate_in" ] && MASSCAN_RATE="$rate_in"
      [ -n "$w_in" ] && MAX_NMAP_WORKERS="$w_in"
      if [ -n "$t_in" ]; then
        run_masscan_from_targets "$t_in"
      else
        if [ -f targets.txt ]; then run_masscan_from_file "targets.txt"; else echo "[!] Nenhum target fornecido e targets.txt não existe. Abortando step 1."; continue; fi
      fi
      build_hosts_ports
      if ! run_nmap_per_host; then
        if [ -n "$t_in" ]; then run_nmap_direct_targets "$t_in"; else echo "[!] Nmap não executado por falta de alvos."; fi
      fi
      if [ -n "$d_in" ]; then run_harvester_for_domains "$d_in"
      else if [ -f domains.txt ]; then run_harvester_for_domains "$(tr '\n' ' ' < domains.txt)"; fi
      fi
      run_aggregate
      ;;
    2)
      read -rp "Targets (space-separated) or press Enter to use targets.txt: " t_in
      read -rp "Masscan rate (default $MASSCAN_RATE): " rate_in
      [ -n "$rate_in" ] && MASSCAN_RATE="$rate_in"
      if [ -n "$t_in" ]; then run_masscan_from_targets "$t_in"
      else if [ -f targets.txt ]; then run_masscan_from_file "targets.txt"; else echo "[!] Nenhum target fornecido e targets.txt não existe."; fi
      fi
      build_hosts_ports
      ;;
    3)
      echo "[*] Nmap confirm/scan"
      if [ -f out/hosts_ports.txt ] && [ -s out/hosts_ports.txt ]; then run_nmap_per_host
      else read -rp "Nenhum resultado masscan — introduz targets (space-separated): " t_in; if [ -n "$t_in" ]; then run_nmap_direct_targets "$t_in"; else echo "[!] Nenhum alvo fornecido."; fi
      fi
      ;;
    4)
      read -rp "Introduz domínios (space-separated) or press Enter to use domains.txt: " d_in
      if [ -n "$d_in" ]; then run_harvester_for_domains "$d_in"
      else if [ -f domains.txt ]; then run_harvester_for_domains "$(tr '\n' ' ' < domains.txt)"; else echo "[!] Nenhum domínio fornecido e domains.txt não existe."; fi
      fi
      ;;
    5)
      echo "[*] Executando aggregator (parse outputs existentes)"
      run_aggregate
      ;;
    6)
      echo "[*] Conteúdo de out/:"
      ls -R out || true
      ;;
    7)
      usage
      ;;
    0)
      echo "Sair."
      exit 0
      ;;
    *)
      echo "Opção inválida."
      ;;
  esac

  echo -e "\nPressiona Enter para voltar ao menu..."
  read -r _
done
