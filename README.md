# BenchjackAuditPage

Static GitHub Pages surface for public BenchJack audit results.

The page is intentionally separate from the BenchJack scanner repo. It reads a generated JSON snapshot from BenchJack audit records and renders a terminal-style results browser for AI researchers.

## Local development

```powershell
python scripts/build_audit_data.py --source C:\Users\volko\Downloads\benchjack --out data\audits.json
python -m http.server 4173
```

Then open `http://127.0.0.1:4173`.

## Data policy

Only committed audit artifacts are shown. Missing files referenced by an audit README are not linked.

