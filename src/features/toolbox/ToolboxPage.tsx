import { useEffect, useMemo, useState } from "react";

import { api, errorText } from "../../lib/api";
import { buildDork, EMPTY_DORK, ENGINES, OPERATOR_SHEET, plan, type DorkSpec } from "../../lib/launchers";
import { ENTITY_PROBE, probeMeta, type EntityType, type Launcher } from "../../lib/types";
import { useStore } from "../../store";

const TYPES: { type: EntityType; label: string; placeholder: string }[] = [
  { type: "username", label: "username", placeholder: "jdoe_dev" },
  { type: "person", label: "name", placeholder: "John Doe" },
  { type: "email", label: "email", placeholder: "jdoe@example.com" },
  { type: "phone", label: "phone", placeholder: "+1 415 555 0100" },
  { type: "domain", label: "domain", placeholder: "example.com" },
  { type: "ip", label: "ip", placeholder: "203.0.113.7" },
  { type: "location", label: "location", placeholder: "40.7128, -74.0060" },
  { type: "org", label: "company", placeholder: "Acme Corp" },
  { type: "wallet", label: "wallet", placeholder: "bc1q…" },
  { type: "image", label: "file", placeholder: "(upload sites)" },
];

export function ToolboxPage() {
  const pushLog = useStore((s) => s.pushLog);
  const requestProbe = useStore((s) => s.requestProbe);
  const [catalog, setCatalog] = useState<Launcher[]>([]);
  const [type, setType] = useState<EntityType>("username");
  const [value, setValue] = useState("");
  const [dork, setDork] = useState<DorkSpec>(EMPTY_DORK);
  const [showSheet, setShowSheet] = useState(false);

  useEffect(() => {
    api
      .launcherCatalog()
      .then(setCatalog)
      .catch((e) => pushLog("bad", `launchers: ${errorText(e)}`));
  }, [pushLog]);

  const planned = useMemo(() => (value.trim() || type === "image" ? plan(catalog, type, value || "x") : []), [catalog, type, value]);
  const grouped = useMemo(() => {
    const map = new Map<string, typeof planned>();
    for (const p of planned) {
      const list = map.get(p.launcher.category) ?? [];
      list.push(p);
      map.set(p.launcher.category, list);
    }
    return [...map.entries()];
  }, [planned]);

  const query = buildDork(dork);
  const meta = TYPES.find((t) => t.type === type)!;
  const probe = ENTITY_PROBE[type];

  const openAll = (items: typeof planned) => {
    for (const p of items) void api.openUrl(p.url);
    pushLog("info", `opened ${items.length} tab${items.length === 1 ? "" : "s"}`);
  };

  return (
    <section className="page wide toolbox">
      <h1>toolbox</h1>
      <p className="muted">
        Hand-operated tools from the field: pick what you have, paste it, and open the sites one at a time or by
        category. The probes emit the same launchers automatically; this page is for quick manual checks.
      </p>

      <h2>Launchers</h2>
      <div className="row" style={{ marginBottom: "0.6rem" }}>
        <div className="seg" role="group" aria-label="Identifier type">
          {TYPES.map((t) => (
            <button key={t.type} type="button" aria-pressed={type === t.type} onClick={() => setType(t.type)}>
              {t.label}
            </button>
          ))}
        </div>
      </div>
      <div className="search-row">
        <input
          className="input lg"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder={meta.placeholder}
          spellCheck={false}
          aria-label="Identifier"
          disabled={type === "image"}
        />
        {probe && probeMeta(probe).available && (
          <button type="button" className="btn primary" disabled={!value.trim()} onClick={() => requestProbe(probe, value)}>
            Run the {probeMeta(probe).label} probe
          </button>
        )}
      </div>

      {grouped.length === 0 ? (
        <p className="muted">Enter a value to see the {catalog.filter((l) => l.types.includes(type)).length} tools for this type.</p>
      ) : (
        grouped.map(([category, items]) => (
          <div key={category} className="launch-group">
            <div className="row between">
              <span className="label">{category}</span>
              <button type="button" className="btn sm" onClick={() => openAll(items)}>
                Open all {items.length}
              </button>
            </div>
            <div className="launch-grid">
              {items.map((p) => (
                <button
                  key={p.launcher.name + p.url}
                  type="button"
                  className="launch"
                  title={p.url}
                  onClick={() => api.openUrl(p.url)}
                >
                  <span className="name">
                    {p.launcher.name}
                    {p.launcher.paste && <span className="chip static">paste</span>}
                  </span>
                  <span className="note">{p.launcher.note}</span>
                </button>
              ))}
            </div>
          </div>
        ))
      )}

      <h2>Dork builder</h2>
      <div className="dork-grid">
        <label>
          <span className="label">exact phrase</span>
          <input className="input" value={dork.exact} onChange={(e) => setDork({ ...dork, exact: e.target.value })} placeholder="john doe" />
        </label>
        <label>
          <span className="label">any of (comma separated)</span>
          <input className="input" value={dork.anyOf} onChange={(e) => setDork({ ...dork, anyOf: e.target.value })} placeholder="resume, cv, portfolio" />
        </label>
        <label>
          <span className="label">exclude</span>
          <input className="input" value={dork.exclude} onChange={(e) => setDork({ ...dork, exclude: e.target.value })} placeholder="citigroup" />
        </label>
        <label>
          <span className="label">site</span>
          <input className="input" value={dork.site} onChange={(e) => setDork({ ...dork, site: e.target.value })} placeholder="facebook.com or de.linkedin.com" />
        </label>
        <label>
          <span className="label">country tld (if no site)</span>
          <input className="input" value={dork.tld} onChange={(e) => setDork({ ...dork, tld: e.target.value })} placeholder="ca" />
        </label>
        <label>
          <span className="label">filetype</span>
          <input className="input" value={dork.filetype} onChange={(e) => setDork({ ...dork, filetype: e.target.value })} placeholder="pdf, xlsx" />
        </label>
        <label>
          <span className="label">inurl</span>
          <input className="input" value={dork.inurl} onChange={(e) => setDork({ ...dork, inurl: e.target.value })} placeholder="profile" />
        </label>
        <label>
          <span className="label">intitle</span>
          <input className="input" value={dork.intitle} onChange={(e) => setDork({ ...dork, intitle: e.target.value })} placeholder="index of" />
        </label>
        <label>
          <span className="label">number range</span>
          <div className="row">
            <input className="input" value={dork.rangeFrom} onChange={(e) => setDork({ ...dork, rangeFrom: e.target.value })} placeholder="2001" />
            <span className="mono">..</span>
            <input className="input" value={dork.rangeTo} onChange={(e) => setDork({ ...dork, rangeTo: e.target.value })} placeholder="2026" />
          </div>
        </label>
        <label>
          <span className="label">social prefix</span>
          <div className="seg" role="group" aria-label="Social prefix">
            {([
              ["", "none"],
              ["@", "@handle"],
              ["#", "#tag"],
            ] as const).map(([v, label]) => (
              <button key={v} type="button" aria-pressed={dork.social === v} onClick={() => setDork({ ...dork, social: v })}>
                {label}
              </button>
            ))}
          </div>
        </label>
      </div>
      <div className="dork-out">
        <code className="mono">{query || "…"}</code>
        <div className="row">
          {ENGINES.map((e) => (
            <button key={e.name} type="button" className="btn sm" disabled={!query} onClick={() => api.openUrl(e.url(query))}>
              {e.name}
            </button>
          ))}
          <button
            type="button"
            className="btn sm"
            disabled={!query}
            onClick={() => navigator.clipboard.writeText(query).then(() => pushLog("info", "dork copied")).catch(() => pushLog("warn", "clipboard unavailable"))}
          >
            Copy
          </button>
          <button type="button" className="btn sm" onClick={() => setDork(EMPTY_DORK)}>
            Clear
          </button>
        </div>
      </div>

      <button type="button" className="btn sm" style={{ marginTop: "1rem" }} aria-pressed={showSheet} onClick={() => setShowSheet((v) => !v)}>
        {showSheet ? "Hide" : "Show"} operator cheat sheet
      </button>
      {showSheet && (
        <table className="grid" style={{ marginTop: "0.6rem", maxWidth: 900 }}>
          <tbody>
            {OPERATOR_SHEET.map(([op, meaning]) => (
              <tr key={op}>
                <td className="mono" style={{ whiteSpace: "nowrap" }}>{op}</td>
                <td style={{ whiteSpace: "normal" }}>{meaning}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
