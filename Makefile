# ──────────────────────────────────────────────
# network-proxy — convenience targets
# ──────────────────────────────────────────────
.PHONY: proxy dashboard viewer debug cert install clean prune watch

## Start the proxy (reads config.json if present)
proxy:
	python proxy.py

## Start with a custom port
proxy-port:
	python proxy.py --port 9090

## Start proxy and only capture the domains you care about
proxy-filter:
	python proxy.py --include-domains "github.com,api.example.com"

## Open the web dashboard
dashboard:
	python dashboard.py

## Show captured domains summary
viewer:
	python viewer.py

## Verbose TLS / hook tracer
debug:
	python debug_proxy.py

## Find and install mitmproxy CA cert
cert:
	python find_cert.py

## Install Python dependencies
install:
	pip install -r requirements.txt

## Export everything to HAR + JSON
export:
	python viewer.py --export report.har
	python viewer.py --export report.json
	python viewer.py --export report.csv

## Prune rows older than 7 days
prune:
	python viewer.py --prune --older-than 7

## Live-tail new requests
watch:
	python viewer.py --watch

## Show DB statistics
stats:
	python viewer.py --stats

## Remove generated output files
clean:
	-del /Q report.har report.json report.csv 2>nul || rm -f report.har report.json report.csv
