# Reconnaissance Automation Pipeline

Este projeto implementa uma pipeline de **reconhecimento automatizado**, combinando ferramentas como **Masscan**, **Nmap** e **theHarvester** para identificar hosts, portas, serviços e recolher OSINT.

## Objetivo
	Automatizar um fluxo básico de reconhecimento:
	  Fase 1 - Colecta de dados: 
		1. **Masscan** — Descoberta rápida de hosts e portas abertas.
		2. **Nmap** — Detecção detalhada de serviços, versões e sistema operativo.
	  Fase 2 - OSINT
		3. **theHarvester** — Recolha de informações públicas (OSINT).  
	  Fase 3 - Agragação
		4. **Aggregation Tool** — Consolidação dos resultados em ficheiros JSON e CSV (aggregate.py)
	  Fase 4 - Relatório Automático
		5. **Report** - Consolidação dos resultados num documento PDF (report_generator.py)

## Estrutura do Projeto
recon-project/
├── run_recon.sh                # Orquestrador (menu + CLI)
├── README.md
├── .gitignore
├── tools/
│   ├── aggregate.py            # Parse e agregação (Python)
│   ├── diff_inventory.py       # Comparador entre runs
│   └── report_generator.py     # Geração de report.md / report.pdf
├── out/                        # Saída do pipeline (criadas automaticamente)
│   ├── masscan.json
│   ├── nmap/
│   ├── harvester/
│   ├── inventory.json
│   ├── inventory.csv
│   ├── inventory.dot
│   ├── inventory.png
│   └── report.pdf
├── targets.txt                 # (opcional) lista de IPs/CIDRs autorizados
└── domains.txt                 # (opcional) lista de domínios para theHarvester


## Execução
Executa a pipeline completa (Masscan → Nmap → theHarvester → Aggregator → Report):

	sudo ./run_recon.sh

O script irá:

1. Pedir o domínio ou IP alvo.
2. Executar masscan e nmap com parâmetros otimizados.
3. Correr theHarvester (sem APIs externas por padrão).
4. Consolidar tudo com aggregate.py.
5. Gerar automaticamente o relatório out/report.pdf.

## Saída Esperada

Após a execução completa, o diretório out/ conterá:

Ficheiro	Descrição
inventory.json	Dados agregados em formato JSON
inventory.csv	Versão tabular dos resultados
inventory.dot	Grafo de hosts e portas
inventory.png	Visualização gráfica
report.pdf	Relatório final (com imagem e resumo)

## Aviso Legal
Este projeto deve ser utilizado apenas em ambientes e sistemas para os quais tenhas autorização explícita.
O uso não autorizado destas ferramentas pode violar leis locais e políticas de segurança.

## Melhoria Futura

1. Integração de busca de CVEs a partir de banners e versões de serviços.
2. Inclusão de WHOIS e SSL info.
3. Melhorias gráficas no PDF (cores e tabelas).
4. Exportação em formatos alternativos (HTML, DOCX)
5. Intergração do portscanner e direcroryscanner desenvolvidos sem nmap e gobuster 
