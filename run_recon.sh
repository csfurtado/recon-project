#!/usr/bin/env bash
# run_recon.sh — Orquestrador Recon Pipeline (com resolução automática de domínios)
set -euo pipefail
# Determine owner (if run with sudo, use original user)
if [ -n "${SUDO_USER-}" ]; then
  OWNER="$SUDO_USER"
else
  OWNER="$USER"
fi

# Defaults
OUTDIR="out"
MASSCAN_JSON="$OUTDIR/masscan.json"
NMAP_OUTDIR="$OUTDIR/nmap"
HARV_OUTDIR="$OUTDIR/harvester"
MASSCAN_RATE=500
MAX_NMAP_WORKERS=6
# NOTE: remove -p- from NMAP_EXTRA_ARGS so we only pass -p once (either -p <ports> or -p-)
NMAP_EXTRA_ARGS="-sC -sV -O"

# -----------------------
# Função de ajuda
# -----------------------
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

ensure_dirs() {
  mkdir -p "$OUTDIR" "$NMAP_OUTDIR" "$HARV_OUTDIR"
  # ensure correct ownership so that later sudo-created files won't block user
  sudo chown -R "$OWNER":"$OWNER" "$OUTDIR" || true
}

chown_out() {
  # Called after any sudo command that may create root-owned files
  if command -v sudo >/dev/null 2>&1; then
    sudo chown -R "$OWNER":"$OWNER" "$OUTDIR" || true
  fi
}

resolve_domains_to_ips() {
  local domains="$1"
  local ips=""
  mkdir -p "$OUTDIR"
  local mapfile="$OUTDIR/domain_ip_map.txt"
  echo "" > "$mapfile"
  for d in $domains; do
    echo "[*] A resolver domínio: $d" >&2
    ip=$(dig +short "$d" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n1)
    if [ -n "$ip" ]; then
      echo "    -> $d resolve para $ip" >&2
      echo "$d -> $ip" >> "$mapfile"
      ips="$ips $ip"
    else
      echo "    [!] Não foi possível resolver $d" >&2
    fi
  done
  # trim leading whitespace
  echo "$ips" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//'
}

run_masscan_from_file() {
  local file="$1"
  echo "[*] masscan (file) -> $file"
  sudo masscan -iL "$file" -p1-65535 --rate "$MASSCAN_RATE" -oJ "$MASSCAN_JSON"
  chown_out
}
run_masscan_from_targets() {
  local tgt="$1"
  # if empty, don't call masscan
  if [ -z "${tgt// /}" ]; then
    echo "[!] run_masscan_from_targets called with empty targets; skipping masscan."
    return 1
  fi
  echo "[*] masscan (targets) -> $tgt"
  sudo masscan $tgt -p1-65535 --rate "$MASSCAN_RATE" -oJ "$MASSCAN_JSON"
  chown_out
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
        byip[ip].append(int(p.get("port")))
with open("out/hosts_ports.txt","w") as f:
    for ip,ports in byip.items():
        ports_sorted = sorted(set(ports))
        # write ports as comma-separated (nmap expects comma-separated)
        f.write(f"{ip} {','.join(str(p) for p in ports_sorted)}\n")
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

      # normalize ports: replace spaces/newlines with commas and remove trailing commas
      ports_clean=$(echo "$ports" | tr ' ' ',' | tr '\n' ',' | sed 's/,,*/,/g' | sed 's/^,//; s/,$//')

      # if ports_clean is empty, fallback to scanning all ports
      if [ -z "$ports_clean" ]; then
        echo "[nmap] $ip -> (no ports listed) using -p- (full port scan)"
        sudo nmap $NMAP_EXTRA_ARGS -p- -oX "$outfile" "$ip" || echo "[!] nmap erro em $ip"
      else
        echo "[nmap] $ip -> $ports_clean"
        sudo nmap $NMAP_EXTRA_ARGS -p "$ports_clean" -oX "$outfile" "$ip" || echo "[!] nmap erro em $ip"
      fi
    }
    export -f run_nmap
    export NMAP_EXTRA_ARGS
    export NMAP_OUTDIR
    # read pairs ip ports from hosts_ports.txt and run in parallel
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
    # full port scan for direct targets
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

run_aggregate() {
  if [ -f tools/aggregate.py ]; then
    echo "[*] Running Python aggregator (tools/aggregate.py)"
    python3 tools/aggregate.py --masscan "$MASSCAN_JSON" --nmapdir "$NMAP_OUTDIR" --outdir "$OUTDIR"
    return $?
  fi
  echo "[!] tools/aggregate.py not found; skipping aggregation."
  return 1
}

# -----------------------
# Parse arguments
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
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    *) break ;;
  esac
done

# Assemble targets/domains
if [ -n "$TARGETS_CLI" ]; then
  TARGETS="$TARGETS_CLI"
elif [ -n "$TARGETS_FILE" ]; then
  TARGETS="$(tr '\n' ' ' < "$TARGETS_FILE" | sed 's/[[:space:]]\+/ /g')"
elif [ -f "targets.txt" ]; then
  TARGETS="$(tr '\n' ' ' < targets.txt | sed 's/[[:space:]]\+/ /g')"
else
  TARGETS=""
fi

if [ -n "$DOMAINS_CLI" ]; then
  DOMAINS="$DOMAINS_CLI"
elif [ -n "$DOMAINS_FILE" ]; then
  DOMAINS="$(tr '\n' ' ' < "$DOMAINS_FILE" | sed 's/[[:space:]]\+/ /g')"
elif [ -f "domains.txt" ]; then
  DOMAINS="$(tr '\n' ' ' < domains.txt | sed 's/[[:space:]]\+/ /g')"
else
  DOMAINS=""
fi

# Resolver domínios se não houver targets
if [ -z "$TARGETS" ] && [ -n "$DOMAINS" ]; then
  echo "[*] Nenhum target fornecido, mas domínios disponíveis. A resolver..."
  TARGETS=$(resolve_domains_to_ips "$DOMAINS")
  echo "[*] IPs resolvidos a partir de domínios: $TARGETS"
fi

# -----------------------
# Gerar report automaticamente (se existir o report_generator)
# -----------------------
generate_report_if_possible() {
  # prefer owner variable se existir (definida no topo do script)
  REPORT_AUTHOR="${OWNER:-${SUDO_USER:-${USER:-unknown}}}"
  if [ -f tools/report_generator.py ]; then
    echo "[*] Gerando relatório automático com tools/report_generator.py..."
    python3 tools/report_generator.py --outdir "$OUTDIR" --repo "Recon Automation" --author "$REPORT_AUTHOR" || echo "[!] Falha ao gerar report (tools/report_generator.py)"
    echo "[*] report.md gerado em $OUTDIR/report.md"
  else
    echo "[*] tools/report_generator.py não encontrado — a saltar geração de relatório."
  fi
}

# -----------------------
# CLI (sem menu)
# -----------------------

if [ -n "$TARGETS" ] || [ -n "$DOMAINS" ]; then
  ensure_dirs
  echo "[*] Targets: $TARGETS"
  echo "[*] Domains: $DOMAINS"
  echo "[*] Masscan rate: $MASSCAN_RATE"
  echo "[*] Max nmap workers: $MAX_NMAP_WORKERS"

  run_masscan_from_targets "$TARGETS" || true
  build_hosts_ports

  if run_nmap_per_host; then
    echo "[*] Nmap per-host concluído"
  else
    run_nmap_direct_targets "$TARGETS"
  fi

  if [ -n "$DOMAINS" ]; then run_harvester_for_domains "$DOMAINS"; fi

  # backup previous inventory if exists
  if [ -f "$OUTDIR/inventory.json" ]; then
    ts=$(date +%F_%H%M%S)
    cp "$OUTDIR/inventory.json" "$OUTDIR/inventory.json.$ts.bak"
    echo "[*] Backed up previous inventory to $OUTDIR/inventory.json.$ts.bak"
  fi

  run_aggregate
  echo "[*] Pipeline concluída. Outputs em $OUTDIR"
  exit 0
fi

# ==========================
# Geração automática do relatório
# ==========================

echo "[*] Limpando relatórios antigos..."
rm -f out/report.md out/report.pdf

echo "[*] Gerando relatório automático..."
python3 tools/report_generator.py --outdir out --repo "Recon Automation" --author "Claudia"

if [ -f out/report.pdf ]; then
    echo "[+] Relatório criado com sucesso: out/report.pdf"
    # Abrir PDF automaticamente (Linux desktop)
    xdg-open out/report.pdf >/dev/null 2>&1 &
else
    echo "[!] Falha ao gerar relatório."
fi

# -----------------------
# Menu interativo
# -----------------------
ensure_dirs
while true; do
  cat <<MENU

===========================================
 Recon Pipeline — Menu Interactivo
===========================================
  1) Run FULL pipeline (Masscan -> Nmap -> theHarvester -> Aggregate)
  2) Run Masscan only
  3) Run Nmap only
  4) Run theHarvester only
  5) Aggregate only
  6) Show outputs
  7) Help
  0) Exit
===========================================
MENU

  read -rp "Opção: " opt
  case "$opt" in
    1)
      read -rp "Targets (IPs) ou Enter: " t_in
      read -rp "Domínios (space-separated) ou Enter: " d_in
      [ -z "$t_in" ] && [ -n "$d_in" ] && t_in=$(resolve_domains_to_ips "$d_in")
      read -rp "Masscan rate (default $MASSCAN_RATE): " rate_in
      [ -n "$rate_in" ] && MASSCAN_RATE="$rate_in"

      run_masscan_from_targets "$t_in" || true
      build_hosts_ports
      run_nmap_per_host || run_nmap_direct_targets "$t_in"
      [ -n "$d_in" ] && run_harvester_for_domains "$d_in"
      run_aggregate
      generate_report_if_possible
      ;;
    2)
      read -rp "Targets ou Enter: " t_in
      run_masscan_from_targets "$t_in"
      build_hosts_ports
      ;;
    3)
      read -rp "Targets ou Enter: " t_in
      run_nmap_direct_targets "$t_in"
      ;;
    4)
      read -rp "Domínios ou Enter: " d_in
      run_harvester_for_domains "$d_in"
      ;;
    5)
      run_aggregate
      generate_report_if_possible
      ;;
    6)
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
  read -rp "Enter para continuar..."
done
