import { useState } from "react";

import { api } from "../lib/api";
import { ENTITY_PROBE, probeMeta } from "../lib/types";
import { selectSelectedFinding, useStore } from "../store";

const statusLabel = {
  found: "Found",
  notFound: "Not found",
  ambiguous: "Ambiguous",
  error: "Error",
  info: "Info",
} as const;

export function Inspector() {
  const finding = useStore(selectSelectedFinding);
  const scan = useStore((s) => (s.selection ? s.scans[s.selection.scanId] : undefined));
  const pushLog = useStore((s) => s.pushLog);
  const requestProbe = useStore((s) => s.requestProbe);
  const [showData, setShowData] = useState(false);

  if (!finding) {
    return (
      <aside className="inspector">
        <h2>Inspector</h2>
        <p className="hint">
          Select a result to see how it was detected, open it in your browser, copy the URL, or pivot on anything it
          revealed.
        </p>
      </aside>
    );
  }

  const copy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      pushLog("info", `copied ${text}`);
    } catch {
      pushLog("warn", "clipboard unavailable");
    }
  };

  const hasData = finding.data !== null && finding.data !== undefined && typeof finding.data === "object";

  return (
    <aside className="inspector">
      <h2>Inspector</h2>
      <div className="site-name">{finding.title}</div>
      <span className={`status ${finding.status}`}>{statusLabel[finding.status]}</span>
      {finding.summary && <p className="summary">{finding.summary}</p>}

      <dl className="kv-list">
        <dt>Input</dt>
        <dd>{scan?.input}</dd>
        <dt>Source</dt>
        <dd>{finding.source}</dd>
        <dt>Kind</dt>
        <dd>{finding.kind}</dd>
        {finding.category && (
          <>
            <dt>Category</dt>
            <dd>{finding.category}</dd>
          </>
        )}
        {finding.url && (
          <>
            <dt>URL</dt>
            <dd>{finding.url}</dd>
          </>
        )}
        {finding.httpStatus !== null && (
          <>
            <dt>HTTP</dt>
            <dd>{finding.httpStatus}</dd>
          </>
        )}
        <dt>Time</dt>
        <dd>{finding.elapsedMs} ms</dd>
        {finding.detail && (
          <>
            <dt>Note</dt>
            <dd>{finding.detail}</dd>
          </>
        )}
      </dl>

      <div className="actions">
        {finding.url && (
          <>
            <button type="button" className="btn primary" onClick={() => api.openUrl(finding.url!)}>
              Open in browser
            </button>
            <button type="button" className="btn" onClick={() => copy(finding.url!)}>
              Copy URL
            </button>
          </>
        )}
        {hasData && (
          <button type="button" className="btn" aria-pressed={showData} onClick={() => setShowData((v) => !v)}>
            Raw data
          </button>
        )}
      </div>

      {showData && hasData && <pre className="data">{JSON.stringify(finding.data, null, 2)}</pre>}

      {finding.discovered.length > 0 && (
        <>
          <h2 style={{ marginTop: "1.2rem" }}>Discovered</h2>
          <ul className="discovered">
            {finding.discovered.map((d, i) => {
              const probe = ENTITY_PROBE[d.type];
              const meta = probe ? probeMeta(probe) : null;
              return (
                <li key={`${d.type}-${d.value}-${i}`}>
                  <span className="chip static">{d.type}</span>
                  <span className="val" title={d.label ?? undefined}>
                    {d.value}
                  </span>
                  <button
                    type="button"
                    className="btn sm"
                    disabled={!meta?.available}
                    title={meta?.available ? `Run the ${meta.label} probe on this` : "Probe not available yet"}
                    onClick={() => probe && requestProbe(probe, d.value)}
                  >
                    Pivot
                  </button>
                </li>
              );
            })}
          </ul>
        </>
      )}

      {finding.status === "ambiguous" && (
        <p className="hint" style={{ marginTop: "1rem" }}>
          The site answered, but the response matched neither the "exists" nor the "missing" signature. Open it and
          check by eye. Sites behind a CAPTCHA or Cloudflare often land here.
        </p>
      )}
    </aside>
  );
}
