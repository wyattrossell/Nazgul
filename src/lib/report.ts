import type { Case, Entity, Finding, Note, ScanRow } from "./types";

function esc(s: unknown): string {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function when(ms: number | null): string {
  return ms ? new Date(ms).toISOString().replace("T", " ").slice(0, 19) + " UTC" : "";
}

export interface ReportInput {
  caseInfo: Case;
  entities: Entity[];
  scans: ScanRow[];
  hits: Finding[];
  notes: Note[];
  version: string;
}

/** Self-contained HTML report. Prints cleanly to PDF from any browser. */
export function buildCaseReport({ caseInfo, entities, scans, hits, notes, version }: ReportInput): string {
  const byScan = new Map<string, Finding[]>();
  for (const f of hits) {
    const list = byScan.get(f.scanId) ?? [];
    list.push(f);
    byScan.set(f.scanId, list);
  }
  const generated = when(Date.now());

  const entityRows = entities
    .map(
      (e) => `<tr><td><code>${esc(e.type)}</code></td><td>${esc(e.value)}${e.label ? ` <span class="muted">(${esc(e.label)})</span>` : ""}</td><td class="num">${e.foundCount}</td><td>${e.tags.map((t) => `<span class="tag">#${esc(t)}</span>`).join(" ")}</td><td class="muted">${when(e.createdAt)}</td></tr>`,
    )
    .join("");

  const scanSections = scans
    .map((s) => {
      const list = (byScan.get(s.id) ?? []).filter((f) => f.kind !== "launcher");
      const rows = list
        .map(
          (f) => `<tr><td>${esc(f.source)}</td><td><code>${esc(f.kind)}</code></td><td>${esc(f.title)}${f.summary ? `<div class="muted">${esc(f.summary)}</div>` : ""}</td><td>${f.url ? `<a href="${esc(f.url)}">${esc(f.url.replace(/^https?:\/\//, ""))}</a>` : ""}</td><td>${f.discovered.map((d) => `<code>${esc(d.type)}</code> ${esc(d.value)}`).join("<br>")}</td></tr>`,
        )
        .join("");
      return `<section>
  <h3>${esc(s.probe)} probe · ${esc(s.input)}</h3>
  <p class="muted">${when(s.startedAt)} · ${esc(s.status)} · ${s.found} hits of ${s.checked} checks${s.elapsedMs ? ` · ${(s.elapsedMs / 1000).toFixed(1)}s` : ""}</p>
  ${rows ? `<table><thead><tr><th>Source</th><th>Kind</th><th>Finding</th><th>Link</th><th>Discovered</th></tr></thead><tbody>${rows}</tbody></table>` : `<p class="muted">No hits recorded.</p>`}
</section>`;
    })
    .join("\n");

  const noteBlocks = notes.map((n) => `<div class="note"><div class="muted">${when(n.updatedAt)}</div><p>${esc(n.body).replace(/\n/g, "<br>")}</p></div>`).join("");

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Nazgul report · ${esc(caseInfo.name)}</title>
<style>
  :root { --ink:#1d1a13; --ink2:#5d574a; --line:#cfc6b2; --accent:#0c6b3d; --bg:#f7f3ea; }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 2.5rem 2rem; background: var(--bg); color: var(--ink); font: 14px/1.55 "IBM Plex Sans", "Segoe UI", system-ui, sans-serif; }
  main { max-width: 1100px; margin: 0 auto; }
  h1, h2, h3, code, .mono { font-family: "IBM Plex Mono", Consolas, monospace; }
  h1 { font-size: 26px; margin: 0 0 .25rem; color: var(--accent); letter-spacing: .04em; }
  h2 { font-size: 13px; letter-spacing: .1em; text-transform: uppercase; color: var(--ink2); border-bottom: 1px solid var(--line); padding-bottom: .3rem; margin: 2.2rem 0 .8rem; }
  h3 { font-size: 15px; margin: 1.4rem 0 .2rem; }
  .muted { color: var(--ink2); font-size: 12.5px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; vertical-align: top; padding: .35rem .5rem; border-bottom: 1px solid var(--line); }
  th { font-size: 11px; letter-spacing: .08em; text-transform: uppercase; color: var(--ink2); font-weight: 500; }
  td.num { text-align: right; font-variant-numeric: tabular-nums; }
  code { font-size: 12px; background: rgba(0,0,0,.05); padding: 0 .3em; border-radius: 2px; }
  a { color: var(--accent); word-break: break-all; }
  .tag { font-family: "IBM Plex Mono", monospace; font-size: 11px; color: var(--accent); }
  .kpis { display: flex; gap: 2rem; margin: 1rem 0 0; font-family: "IBM Plex Mono", monospace; font-size: 13px; }
  .kpis b { display: block; font-size: 22px; color: var(--accent); }
  .note { border-left: 2px solid var(--line); padding: .3rem .8rem; margin: .5rem 0; }
  footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--line); font-size: 12px; color: var(--ink2); }
  @media print { body { padding: 0; background: #fff; } a { color: inherit; } }
</style>
</head>
<body>
<main>
  <header>
    <div class="muted mono">NAZGUL CASE REPORT</div>
    <h1>${esc(caseInfo.name)}</h1>
    ${caseInfo.description ? `<p>${esc(caseInfo.description)}</p>` : ""}
    <div class="kpis">
      <span><b>${entities.length}</b>entities</span>
      <span><b>${scans.length}</b>scans</span>
      <span><b>${hits.filter((f) => f.status === "found").length}</b>confirmed hits</span>
      <span><b>${hits.filter((f) => f.status === "info").length}</b>informational</span>
    </div>
    <p class="muted">Generated ${generated} · Nazgul v${esc(version)} · public sources only</p>
  </header>

  <h2>Entities</h2>
  ${entityRows ? `<table><thead><tr><th>Type</th><th>Value</th><th>Hits</th><th>Tags</th><th>Added</th></tr></thead><tbody>${entityRows}</tbody></table>` : `<p class="muted">No entities.</p>`}

  <h2>Scans and findings</h2>
  ${scanSections || `<p class="muted">No scans.</p>`}

  <h2>Notes</h2>
  ${noteBlocks || `<p class="muted">No notes.</p>`}

  <footer>Findings reflect what public sources returned at scan time. Verify anything consequential by hand before acting on it.</footer>
</main>
</body>
</html>`;
}
