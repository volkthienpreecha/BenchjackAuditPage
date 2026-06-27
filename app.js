const state = {
  data: null,
  selectedId: null,
  activeTab: "results",
  filters: {
    search: "",
    severity: "all",
    backend: "all",
    score: 0,
  },
};

const VULN_LABELS = {
  V1: "Isolation",
  V2: "Answers",
  V3: "RCE",
  V4: "LLM Judge",
  V5: "Matching",
  V6: "Logic",
  V7: "Trust",
  V8: "Perms",
};

const STATUS_ORDER = ["major", "critical", "high", "medium", "low", "na"];

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("[data-tab]").forEach((button) => {
    button.addEventListener("click", () => {
      state.activeTab = button.dataset.tab;
      document.querySelectorAll("[data-tab]").forEach((item) => {
        item.classList.toggle("active", item.dataset.tab === state.activeTab);
      });
      document.querySelectorAll("[data-panel]").forEach((panel) => {
        panel.classList.toggle("hidden", panel.dataset.panel !== state.activeTab);
      });
    });
  });

  bindFilters();
  loadData();
});

function bindFilters() {
  const search = document.querySelector("#search");
  const severity = document.querySelector("#severity-filter");
  const backend = document.querySelector("#backend-filter");
  const score = document.querySelector("#score-filter");

  search.addEventListener("input", () => {
    state.filters.search = search.value.trim().toLowerCase();
    render();
  });
  severity.addEventListener("change", () => {
    state.filters.severity = severity.value;
    render();
  });
  backend.addEventListener("change", () => {
    state.filters.backend = backend.value;
    render();
  });
  score.addEventListener("change", () => {
    state.filters.score = Number(score.value || 0);
    render();
  });

  document.querySelector("#export-json").addEventListener("click", exportJson);
  document.querySelector("#copy-link").addEventListener("click", copyLink);
}

async function loadData() {
  try {
    const [paper, audit] = await Promise.all([
      fetchJson("data/paper-study.json"),
      fetchJson("data/audits.json"),
    ]);
    state.data = buildDisplayData(paper, audit);
    state.selectedId = initialSelection(state.data.records);
    hydrateBackendFilter(state.data.records);
    render();
  } catch (error) {
    document.querySelector("#detail").innerHTML = `<div class="detail-empty">failed to load result data: ${escapeHtml(error.message)}</div>`;
  }
}

async function fetchJson(path) {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) throw new Error(`${path}: HTTP ${response.status}`);
  return response.json();
}

function buildDisplayData(paper, audit) {
  const archiveRecords = audit?.records || [];
  const archiveByName = new Map(archiveRecords.map((record) => [normalizeName(record.name), record]));
  const paperRecords = paper?.records?.map((record) => enrichPaperRecord(record, archiveByName.get(normalizeName(record.name)))) || [];
  const records = paperRecords.length
    ? paperRecords
    : archiveRecords.map((record) => ({ ...record, record_source: "audit-archive", source_label: "Audit archive" }));

  if (!records.length) throw new Error("no paper study or audit archive records found");

  return {
    generated_at: paper?.generated_at || audit?.generated_at || "unknown",
    source_label: paperRecords.length ? "paper study" : "audit records",
    source_url: paper?.source?.url || audit?.source?.repo_url || "",
    paper,
    audit,
    archive_records: archiveRecords,
    notes: paper?.notes || [],
    summary: {
      flaw_count: paper?.summary?.flaw_count ?? null,
      table_task_count: paper?.summary?.table_task_count ?? null,
      record_count: records.length,
    },
    records,
  };
}

function enrichPaperRecord(record, archive) {
  return {
    ...record,
    artifacts: archive?.artifacts || [],
    archive_source_path: archive?.source_path || "",
    archive_source_url: archive?.source_url || "",
    disclosure: archive?.disclosure || [],
    record_source: "paper-study",
    reproduction: archive?.reproduction || "",
    upstream_commit: archive?.upstream_commit || "",
    upstream_commit_url: archive?.upstream_commit_url || "",
    upstream_repo: archive?.upstream_repo || record.upstream_repo || "",
  };
}

function normalizeName(value) {
  return String(value || "").toLowerCase().replace(/[^a-z0-9]+/g, "");
}

function initialSelection(records) {
  const hash = window.location.hash.replace(/^#/, "");
  if (hash && records.some((record) => record.id === hash)) return hash;
  return records[0]?.id || null;
}

function hydrateBackendFilter(records) {
  const select = document.querySelector("#backend-filter");
  const seen = new Set([...select.options].map((option) => option.value));
  for (const backend of [...new Set(records.map((record) => record.backend).filter(Boolean))].sort()) {
    if (seen.has(backend)) continue;
    const option = document.createElement("option");
    option.value = backend;
    option.textContent = backend;
    select.appendChild(option);
  }
}

function filteredRecords() {
  if (!state.data) return [];
  return state.data.records.filter((record) => {
    const haystack = [
      record.name,
      record.summary,
      record.exploit_summary,
      record.domain,
      record.evaluation_method,
      record.upstream_repo,
      record.auditor,
      record.backend,
      record.mode,
      record.source_label,
      ...(record.major_flaws || []),
    ].join(" ").toLowerCase();
    if (state.filters.search && !haystack.includes(state.filters.search)) return false;
    if (state.filters.backend !== "all" && record.backend !== state.filters.backend) return false;
    if (state.filters.severity !== "all") {
      const matchesSeverity = Object.values(record.findings).some((finding) => finding.severity === state.filters.severity);
      if (!matchesSeverity) return false;
    }
    if (state.filters.score > 0) {
      if (record.exploit_score === null || record.exploit_score === undefined || Number(record.exploit_score) < state.filters.score) return false;
    }
    return true;
  });
}

function render() {
  if (!state.data) return;
  const records = filteredRecords();
  if (state.selectedId && !records.some((record) => record.id === state.selectedId)) {
    state.selectedId = records[0]?.id || null;
  }
  renderSummary(records);
  renderBenchmarks(records);
  renderMatrix(records);
  renderDetail(records.find((record) => record.id === state.selectedId) || null);
  renderCompare(records);
  renderArtifacts(records);
  renderFooter(records);
}

function renderSummary(records) {
  const taskCount = records.reduce((sum, record) => sum + (record.task_count || 0), 0);
  const scores = records.map((record) => record.exploit_score).filter((score) => score !== null && score !== undefined);
  document.querySelector("#summary-records").textContent = records.length.toLocaleString();
  document.querySelector("#summary-tasks").textContent = taskCount.toLocaleString();
  document.querySelector("#summary-range").textContent = scores.length ? `${formatPercent(Math.min(...scores))}-${formatPercent(Math.max(...scores))}` : "n/a";
  document.querySelector("#summary-source").textContent = state.data.source_label;
  document.querySelector("#summary-updated").textContent = state.data.generated_at;
  document.querySelector("#summary-flaws").textContent = state.data.summary.flaw_count?.toLocaleString() || "n/a";
  document.querySelector("#footer-data-date").textContent = state.data.generated_at;
  document.querySelector("#bench-count").textContent = records.length;
}

function renderBenchmarks(records) {
  const root = document.querySelector("#benchmarks");
  root.innerHTML = "";
  if (records.length === 0) {
    root.innerHTML = `<div class="empty-state">no result records match the current filters</div>`;
    return;
  }
  records.forEach((record, index) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `bench-row ${record.id === state.selectedId ? "active" : ""}`;
    button.innerHTML = `
      <span>
        <span class="bench-name">${index + 1} ${escapeHtml(record.name)}</span>
        <span class="bench-desc">${escapeHtml(record.domain || hostLabel(record.upstream_repo) || record.source_label || "result record")}</span>
      </span>
      <span>${record.task_count ?? "n/a"}</span>
      <span class="bench-score">${scoreLabel(record)}</span>
      <span>${escapeHtml(record.audited_on || "n/a")}</span>
    `;
    button.addEventListener("click", () => selectRecord(record.id));
    root.appendChild(button);
  });
}

function renderMatrix(records) {
  const body = document.querySelector("#matrix-body");
  body.innerHTML = "";
  if (records.length === 0) {
    body.innerHTML = `<tr><td colspan="10" class="empty-cell">no records</td></tr>`;
    return;
  }
  records.forEach((record, index) => {
    const row = document.createElement("tr");
    row.className = record.id === state.selectedId ? "selected" : "";
    row.innerHTML = `
      <td>${index + 1}</td>
      <td><button class="matrix-select" type="button">${escapeHtml(record.name)}</button></td>
      ${Object.keys(VULN_LABELS).map((vuln) => findingCell(record.findings[vuln])).join("")}
    `;
    row.querySelector(".matrix-select").addEventListener("click", () => selectRecord(record.id));
    body.appendChild(row);
  });
}

function findingCell(finding) {
  if (!finding || finding.severity === "na") return `<td class="none-cell">-</td>`;
  return `
    <td title="${escapeHtml(`${finding.id}: ${finding.name} (${finding.prevalence})`)}">
      <span class="severity-cell">
        <i class="dot ${finding.severity}"></i>
        <span>${escapeHtml(scopeLabel(finding.prevalence))}</span>
      </span>
    </td>
  `;
}

function renderDetail(record) {
  const root = document.querySelector("#detail");
  if (!record) {
    root.innerHTML = `<div class="detail-empty">select a result record</div>`;
    return;
  }

  const notes = [...(record.data_notes || []), ...sourceSpecificNotes(record)];
  root.innerHTML = `
    <div class="detail-head">
      <h2>${escapeHtml(record.name)}</h2>
      <button id="close-detail" type="button" aria-label="Clear selection">x</button>
    </div>
    <div class="detail-section meta-grid">
      ${metaRow("source", linkHtml(record.source_url, record.source_label || "paper source"), true)}
      ${record.domain ? metaRow("domain", record.domain) : ""}
      ${record.evaluation_method ? metaRow("evaluation", record.evaluation_method) : ""}
      ${metaRow(record.record_source === "paper-study" ? "table tasks" : "tasks", record.task_count ?? "n/a")}
      ${metaRow("exploit outcome", outcomeLabel(record))}
      ${metaRow("major flaws", majorFlawLabel(record))}
      ${record.upstream_repo ? metaRow("upstream repo", linkHtml(record.upstream_repo, hostLabel(record.upstream_repo)), true) : ""}
      ${record.upstream_commit ? metaRow("upstream commit", linkHtml(record.upstream_commit_url, record.upstream_commit), true) : ""}
      ${metaRow("date", record.audited_on || "n/a")}
      ${metaRow("backend", record.backend || "n/a")}
      ${metaRow("mode", record.mode || "n/a")}
      ${record.archive_source_url ? metaRow("audit archive", linkHtml(record.archive_source_url, record.archive_source_path || "FrontierSWE archive"), true) : ""}
    </div>
    <div class="detail-section">
      <h3>artifacts</h3>
      <div class="artifact-list">
        ${record.artifacts?.length ? record.artifacts.map((artifact) => artifactRow(artifact)).join("") : `<div class="empty-inline">no artifact-backed public archive for this row</div>`}
      </div>
      ${record.archive_source_url ? `<a class="subtle-link" href="${escapeHtml(record.archive_source_url)}" target="_blank" rel="noreferrer">view audit README</a>` : ""}
    </div>
    <div class="detail-section">
      <h3>exploit note</h3>
      <p>${escapeHtml(record.exploit_summary || record.summary)}</p>
      ${record.summary && record.exploit_summary ? `<p class="dim">${escapeHtml(record.summary)}</p>` : ""}
      ${record.reproduction ? `<pre><code>${escapeHtml(record.reproduction)}</code></pre>` : ""}
      ${record.disclosure?.length ? `<p class="dim">${escapeHtml(record.disclosure.join(" "))}</p>` : ""}
      ${notes.length ? `<div class="note-list">${notes.map((note) => `<p>${escapeHtml(note)}</p>`).join("")}</div>` : ""}
    </div>
  `;
  document.querySelector("#close-detail").addEventListener("click", () => {
    state.selectedId = null;
    history.replaceState(null, "", location.pathname);
    render();
  });
}

function sourceSpecificNotes(record) {
  if (record.record_source !== "paper-study") return [];
  return [
    "Matrix dots for paper-study rows represent Table 1 major flaw classes, not a full per-finding severity ledger.",
  ];
}

function renderCompare(records) {
  const root = document.querySelector("#compare-content");
  if (records.length === 0) {
    root.innerHTML = `<div class="empty-state">no records to compare</div>`;
    return;
  }
  root.innerHTML = `
    <table class="compare-table">
      <thead>
        <tr>
          <th>benchmark</th>
          <th>domain</th>
          <th>tasks</th>
          <th>exploit</th>
          <th>major flaws</th>
          ${Object.keys(VULN_LABELS).map((vuln) => `<th>${vuln}</th>`).join("")}
        </tr>
      </thead>
      <tbody>
        ${records.map((record) => `
          <tr>
            <td>${escapeHtml(record.name)}</td>
            <td>${escapeHtml(record.domain || "n/a")}</td>
            <td>${record.task_count ?? "n/a"}</td>
            <td>${escapeHtml(outcomeLabel(record))}</td>
            <td>${escapeHtml(majorFlawLabel(record))}</td>
            ${Object.keys(VULN_LABELS).map((vuln) => {
              const finding = record.findings[vuln] || { severity: "na" };
              return `<td><span class="severity-token ${finding.severity}">${escapeHtml(finding.severity)}</span></td>`;
            }).join("")}
          </tr>
        `).join("")}
      </tbody>
    </table>
  `;
}

function renderArtifacts(records) {
  const root = document.querySelector("#artifacts-content");
  const artifacts = records.flatMap((record) => (record.artifacts || []).map((artifact) => ({ ...artifact, benchmark: record.name })));
  if (artifacts.length === 0) {
    root.innerHTML = `<div class="empty-state">no public artifacts match the current filters</div>`;
    return;
  }
  root.innerHTML = artifacts.map((artifact) => `
    <a class="artifact-wide" href="${escapeHtml(artifact.url)}" target="_blank" rel="noreferrer">
      <span>
        <strong>${escapeHtml(artifact.benchmark)}</strong>
        <em>${escapeHtml(artifact.path)}</em>
      </span>
      <span>${formatBytes(artifact.size_bytes)}</span>
    </a>
  `).join("");
}

function renderFooter(records) {
  const counts = Object.fromEntries(STATUS_ORDER.map((status) => [status, 0]));
  for (const record of records) {
    for (const finding of Object.values(record.findings)) {
      counts[finding.severity] = (counts[finding.severity] || 0) + 1;
    }
  }
  document.querySelector("#severity-counts").innerHTML = `
    <span class="count major">${counts.major || 0} Major</span>
    <span class="count critical">${counts.critical || 0} Critical</span>
    <span class="count high">${counts.high || 0} High</span>
    <span class="count medium">${counts.medium || 0} Medium</span>
    <span class="count low">${counts.low || 0} Low</span>
    <span>|</span>
    <span>${records.length} Total Records</span>
  `;
}

function selectRecord(id) {
  state.selectedId = id;
  history.replaceState(null, "", `#${id}`);
  render();
}

function exportJson() {
  if (!state.data) return;
  const blob = new Blob([JSON.stringify(state.data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = "benchjack-results.json";
  anchor.click();
  URL.revokeObjectURL(url);
}

async function copyLink() {
  const url = `${location.origin}${location.pathname}${state.selectedId ? `#${state.selectedId}` : ""}`;
  try {
    await navigator.clipboard.writeText(url);
    pulseButton("#copy-link", "copied");
  } catch {
    const input = document.createElement("input");
    input.value = url;
    document.body.appendChild(input);
    input.select();
    document.execCommand("copy");
    input.remove();
    pulseButton("#copy-link", "copied");
  }
}

function pulseButton(selector, label) {
  const button = document.querySelector(selector);
  const original = button.textContent;
  button.textContent = label;
  setTimeout(() => {
    button.textContent = original;
  }, 1100);
}

function metaRow(label, value, html = false) {
  const rendered = html ? String(value ?? "") : escapeHtml(value);
  return `<div class="meta-label">${escapeHtml(label)}</div><div class="meta-value">${rendered}</div>`;
}

function artifactRow(artifact) {
  return `
    <a class="artifact-row" href="${escapeHtml(artifact.url)}" target="_blank" rel="noreferrer">
      <span>
        <strong>${escapeHtml(artifact.label)}</strong>
        <em>${escapeHtml(artifact.kind)}</em>
      </span>
      <span>${formatBytes(artifact.size_bytes)}</span>
    </a>
  `;
}

function linkHtml(url, label) {
  if (!url) return "n/a";
  return `<a href="${escapeHtml(url)}" target="_blank" rel="noreferrer">${escapeHtml(label || url)}</a>`;
}

function scoreLabel(record) {
  if (record.exploit_score_label) return record.exploit_score_label;
  return record.exploit_score === null || record.exploit_score === undefined
    ? "n/a"
    : formatPercent(record.exploit_score);
}

function outcomeLabel(record) {
  if (record.exploited_count !== undefined && record.outcome_denominator !== undefined) {
    return `${record.exploited_count.toLocaleString()} / ${record.outcome_denominator.toLocaleString()} exploited (${scoreLabel(record)})`;
  }
  return scoreLabel(record);
}

function majorFlawLabel(record) {
  return record.major_flaws?.length ? record.major_flaws.join(", ") : "n/a";
}

function hostLabel(url) {
  if (!url) return "";
  try {
    const parsed = new URL(url);
    return parsed.pathname.replace(/^\//, "") || parsed.host;
  } catch {
    return url;
  }
}

function scopeLabel(value) {
  if (!value || value === "-") return "-";
  const text = value.toLowerCase();
  if (text.includes("table 1 major")) return "major";
  if (text.startsWith("all ")) return "all";
  if (text.includes("majority")) return "maj";
  if (text.includes("most")) return "most";
  if (text.includes("many")) return "many";
  if (text.includes("multiple")) return "multi";
  if (text.includes("root")) return "root";
  return value;
}

function formatPercent(value) {
  return `${Number(value).toLocaleString(undefined, { maximumFractionDigits: 1 })}%`;
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(bytes > 10 * 1024 ? 0 : 1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
