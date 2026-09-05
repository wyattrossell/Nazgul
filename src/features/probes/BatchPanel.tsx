import { useMemo, useState } from "react";

import { enqueueScans } from "../../lib/scans";
import type { ProbeKind } from "../../lib/types";
import { useStore } from "../../store";

const RE_EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const RE_IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;
const RE_IPV6 = /^[0-9a-f:]+:[0-9a-f:]*$/i;
const RE_DOMAIN = /^(https?:\/\/)?([a-z0-9-]+\.)+[a-z]{2,}(\/.*)?$/i;
const RE_PHONE = /^\+?[\d\s().-]{7,}$/;
const RE_CRYPTO = /^(0x[0-9a-fA-F]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{25,62}|[LM][a-km-zA-HJ-NP-Z1-9]{26,33}|ltc1[a-z0-9]{25,62})$/;
const RE_PERSON = /^[a-z][a-z'.-]*(\s+[a-z][a-z'.-]*){1,3}$/i;

export function detectProbe(line: string): ProbeKind {
  const s = line.trim();
  if (RE_EMAIL.test(s)) return "email";
  if (RE_IPV4.test(s) || RE_IPV6.test(s)) return "ip";
  if (RE_CRYPTO.test(s)) return "crypto";
  if (RE_DOMAIN.test(s)) return "domain";
  if (RE_PHONE.test(s) && /\d{6,}/.test(s.replace(/\D/g, ""))) return "phone";
  if (RE_PERSON.test(s)) return "person";
  return "username";
}

const FORCE: (ProbeKind | "auto")[] = ["auto", "username", "person", "email", "phone", "domain", "ip", "crypto"];

export function BatchPanel({ onClose }: { onClose: () => void }) {
  const pushLog = useStore((s) => s.pushLog);
  const [text, setText] = useState("");
  const [force, setForce] = useState<ProbeKind | "auto">("auto");

  const items = useMemo(() => {
    const seen = new Set<string>();
    return text
      .split(/\r?\n|,|;/)
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith("#") && seen.has(l) === false && seen.add(l))
      .map((input) => ({ input, probe: force === "auto" ? detectProbe(input) : force }));
  }, [text, force]);

  const queue = () => {
    if (items.length === 0) return;
    enqueueScans(items.map((i) => ({ probe: i.probe, input: i.input })));
    pushLog("info", `batch: queued ${items.length} scan${items.length === 1 ? "" : "s"}`);
    setText("");
    onClose();
  };

  return (
    <div className="variants batch">
      <div className="row between">
        <span className="label">batch import · one identifier per line (or comma separated)</span>
        <div className="row">
          <span className="label">treat as</span>
          <select className="input sm" style={{ width: 130 }} value={force} onChange={(e) => setForce(e.target.value as ProbeKind | "auto")} aria-label="Probe for every line">
            {FORCE.map((f) => (
              <option key={f} value={f}>
                {f}
              </option>
            ))}
          </select>
          <button type="button" className="btn sm primary" disabled={items.length === 0} onClick={queue}>
            Queue {items.length || ""} scans
          </button>
          <button type="button" className="btn sm" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
      <textarea
        className="input"
        rows={5}
        value={text}
        onChange={(e) => setText(e.target.value)}
        placeholder={"jdoe_dev\njdoe@example.com\nexample.com\n203.0.113.7\n+1 415 555 0100"}
        spellCheck={false}
        aria-label="Identifiers to scan"
      />
      {items.length > 0 && (
        <div className="variant-grid">
          {items.slice(0, 60).map((i) => (
            <span key={i.input} className="variant">
              <span className="chip static">{i.probe}</span>
              <span className="mono" title={i.input}>
                {i.input}
              </span>
            </span>
          ))}
          {items.length > 60 && <span className="muted">… and {items.length - 60} more</span>}
        </div>
      )}
      <p className="muted">Scans run one after another so shared hosts are not hammered. Each lands in the active case.</p>
    </div>
  );
}
