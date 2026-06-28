# BenchjackAuditPage

Static GitHub Pages surface for public BenchJack audit results.

The page is intentionally separate from the BenchJack scanner repo. It reads a curated paper-study snapshot plus a generated audit-archive snapshot, then renders a terminal-style results browser for AI researchers.

## Local development

```powershell
python scripts/build_audit_data.py --source C:\Users\volko\Downloads\benchjack --repo-url https://github.com/benchjack/benchjack --out data\audits.json
python -m http.server 4173
```

Then open `http://127.0.0.1:4173`.

## Data policy

The default result table is sourced from the BenchJack paper: "Do Androids Dream of Breaking the Game? Systematically Auditing AI Agent Benchmarks with BenchJack" (arXiv:2605.12673).

Chart-only values are not digitized into data. The page includes exact values from the paper text, Table 1, Appendix E, and selected Appendix F patch-study outcomes. The paper's Terminal-Bench denominator mismatch is shown explicitly: Table 1 lists 89 tasks, while Appendix E/F reports exploit and residual outcomes over 241 tasks.

The paper reports 219 distinct flaws in text and labels Figure 6b as 230 per-flaw task-coverage entries. The page shows both values instead of forcing them into one count.

Only committed audit artifacts are shown. Missing files referenced by an audit README are not linked, and paper-study rows do not receive artifact links unless a matching public audit archive exists.
