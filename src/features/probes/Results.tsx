import { useMemo, useState } from "react";

import { api, errorText, saveTextAs } from "../../lib/api";
import { findingsToCsv, safeFileStem, scanToJson } from "../../lib/export";
import type { Finding, FindingStatus } from "../../lib/types";
import { useStore, type Scan, type StatusFilter } from "../../store";

const statusOrder: Record<FindingStatus, number> = { found: 0, info: 1, ambiguous: 2, error: 3, notFound: 4 };
const statusText: Record<FindingStatus, string> = {
  found: "found",
  info: "info",
  ambiguous: "check",
  error: "error",
  notFound: "none",
};

type SortKey = "source" | "status" | "category" | "elapsedMs" | "kind";

interface Row {
  finding: Finding;
  index: number;
}

export function Results({ scan }: { scan: Scan | null }) {
  const layout = useStore((s) => s.settings.resultsLayout);
  const setSettings = useStore((s) => s.setSettings);
  const selection = useStore((s) => s.selection);
  const select = useStore((s) => s.select);
  const pushLog = useStore((s) => s.pushLog);

  const [filter, setFilter] = useState<StatusFilter>("hits");
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState<{ key: SortKey; dir: 1 | -1 }>({ key: "status", dir: 1 });

  const rows = useMemo<Row[]>(() => {
    if (!scan) return [];
    const q = query.trim().toLowerCase();
    const list = scan.findings
      .map((finding, index) => ({ finding, index }))
      .filter(({ finding: f }) => {
        if (filter === "hits" && f.status !== "found" && f.status !== "info") return false;
        if (filter === "issues" && f.status !== "ambiguous" && f.status !== "error") return false;
        if (q && !`${f.source} ${f.title} ${f.category} ${f.kind} ${f.url ?? ""} ${f.summary ?? ""}`.toLowerCase().includes(q))
          return false;
        return true;
      });
    const { key, dir } = sort;
    return list.sort(({ finding: a }, { finding: b }) => {
      let cmp = 0;
      if (key === "status") cmp = statusOrder[a.status] - statusOrder[b.status];
      else if (key === "elapsedMs") cmp = a.elapsedMs - b.elapsedMs;
      else cmp = a[key].localeCompare(b[key]);
      if (cmp === 0) cmp = a.title.localeCompare(b.title);
      return cmp * dir;
    });
  }, [scan, filter, query, sort]);

  if (!scan) {
    return (
      <div className="results">
        <div className="empty">
          <div className="big">NO SCAN</div>
          Enter an identifier above and run it. Results stream in as each check answers. Hits show first.
        </div>
      </div>
    );
  }

  const counts = scan.findings.reduce(
    (acc, f) => {
      acc[f.status] += 1;
      return acc;
    },
    { found: 0, notFound: 0, ambiguous: 0, error: 0, info: 0 } as Record<FindingStatus, number>,
  );

  const isSelected = (index: number) => selection?.scanId === scan.id && selection.index === index;
  const choose = (index: number) => select({ scanId: scan.id, index });
  const open = (f: Finding) => f.url && api.openUrl(f.url);

  const exportAs = async (kind: "json" | "csv") => {
    try {
      const stem = `nazgul-${scan.probe}-${safeFileStem(scan.input)}`;
      const path =
        kind === "json"
          ? await saveTextAs(`${stem}.json`, "json", scanToJson(scan))
          : await saveTextAs(`${stem}.csv`, "csv", findingsToCsv(scan.findings));
      if (path) pushLog("ok", `exported ${path}`);
    } catch (err) {
      pushLog("bad", `export failed: ${errorText(err)}`);
    }
  };

  const sortBy = (key: SortKey) =>
    setSort((s) => (s.key === key ? { key, dir: s.dir === 1 ? -1 : 1 } : { key, dir: 1 }));

  const hits = counts.found + counts.info;

  return (
    <>
      <div className="results-bar">
        <span className="summary">
          {scan.input} · <b>{hits} hits</b>
          {counts.notFound > 0 && ` · ${counts.notFound} none`}
          {counts.ambiguous > 0 && ` · ${counts.ambiguous} check`}
          {counts.error > 0 && ` · ${counts.error} errors`} · {scan.checked}/{scan.total}
          {scan.elapsedMs !== null && ` · ${(scan.elapsedMs / 1000).toFixed(1)}s`}
          {scan.error && <span className="status error"> · {scan.error}</span>}
        </span>

        <div className="seg" role="group" aria-label="Filter">
          {(["hits", "all", "issues"] as StatusFilter[]).map((k) => (
            <button key={k} type="button" aria-pressed={filter === k} onClick={() => setFilter(k)}>
              {k}
            </button>
          ))}
        </div>

        <input
          className="input filter"
          placeholder="filter…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          aria-label="Filter results"
        />

        <div className="seg" role="group" aria-label="Layout">
          <button type="button" aria-pressed={layout === "cards"} onClick={() => setSettings({ resultsLayout: "cards" })}>
            cards
          </button>
          <button type="button" aria-pressed={layout === "table"} onClick={() => setSettings({ resultsLayout: "table" })}>
            table
          </button>
        </div>

        <button type="button" className="btn sm" onClick={() => exportAs("json")} disabled={scan.findings.length === 0}>
          JSON
        </button>
        <button type="button" className="btn sm" onClick={() => exportAs("csv")} disabled={scan.findings.length === 0}>
          CSV
        </button>
      </div>

      <div className="results">
        {rows.length === 0 ? (
          <div className="empty">
            {scan.status === "running" && scan.findings.length === 0
              ? "Waiting for the first responses…"
              : filter === "hits"
                ? 'No hits yet. Switch the filter to "all" to see every check.'
                : "Nothing matches this filter."}
          </div>
        ) : layout === "cards" ? (
          <div className="cards">
            {rows.map(({ finding: f, index }) => (
              <div
                key={index}
                className="card"
                role="button"
                tabIndex={0}
                aria-selected={isSelected(index)}
                onClick={() => choose(index)}
                onDoubleClick={() => open(f)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") choose(index);
                }}
              >
                <div className="row">
                  <span className="site" title={f.title}>
                    {f.title}
                  </span>
                  <span className={`status ${f.status}`}>{statusText[f.status]}</span>
                </div>
                {f.url ? (
                  <span className="url" title={f.url}>
                    {f.url.replace(/^https?:\/\//, "")}
                  </span>
                ) : (
                  f.summary && <span className="url">{f.summary}</span>
                )}
                <div className="meta">
                  <span>{f.source !== f.title ? f.source : f.kind}</span>
                  {f.category && <span>{f.category}</span>}
                  {f.httpStatus !== null && <span>{f.httpStatus}</span>}
                  <span>{f.elapsedMs} ms</span>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <table className="grid">
            <thead>
              <tr>
                <th onClick={() => sortBy("source")}>Source</th>
                <th onClick={() => sortBy("kind")}>Kind</th>
                <th onClick={() => sortBy("status")}>Status</th>
                <th>Title</th>
                <th onClick={() => sortBy("category")}>Category</th>
                <th>HTTP</th>
                <th onClick={() => sortBy("elapsedMs")}>ms</th>
                <th>URL / summary</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(({ finding: f, index }) => (
                <tr key={index} aria-selected={isSelected(index)} onClick={() => choose(index)} onDoubleClick={() => open(f)}>
                  <td>{f.source}</td>
                  <td>{f.kind}</td>
                  <td>
                    <span className={`status ${f.status}`}>{statusText[f.status]}</span>
                  </td>
                  <td>{f.title}</td>
                  <td>{f.category}</td>
                  <td className="num">{f.httpStatus ?? "—"}</td>
                  <td className="num">{f.elapsedMs}</td>
                  <td title={f.url ?? f.summary ?? ""}>{f.url ?? f.summary ?? ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
