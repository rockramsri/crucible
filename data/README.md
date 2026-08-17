# Data

Committed scan input and a sample validation run against self-hosted OWASP Juice Shop.

```
data/
  zap/juiceshop/          scanner input
    juiceshop_zap_baseline.json   passive / spider only
    juiceshop_zap_full.json       bounded full active scan
    zap.yaml                      ZAP automation config used for baseline
  output/juiceshop/       Crucible output for that full scan
    validation_report.json
    llm_trace.jsonl
```

Re-run the scan:

```bash
SCAN=full ./scripts/run_zap_juiceshop.sh
```

Re-run validation (Juice Shop must be up on the `pentest` Docker network):

```bash
python -m crucible.cli data/zap/juiceshop/juiceshop_zap_full.json \
    --target http://juiceshop:3000 --backend docker
```
