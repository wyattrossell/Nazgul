import { useEffect, useState } from "react";

import { api } from "../lib/api";
import { useStore, type View } from "../store";

const items: { view: View; label: string; phase?: string }[] = [
  { view: "probes", label: "Probes", phase: "ctrl 1" },
  { view: "cases", label: "Cases", phase: "ctrl 2" },
  { view: "graph", label: "Graph", phase: "ctrl 3" },
  { view: "history", label: "History", phase: "ctrl 4" },
  { view: "settings", label: "Settings", phase: "ctrl 5" },
];

export function Rail() {
  const view = useStore((s) => s.view);
  const setView = useStore((s) => s.setView);
  const [version, setVersion] = useState("");

  useEffect(() => {
    api
      .appInfo()
      .then((info) => setVersion(`v${info.version} · ${info.siteCount} sites`))
      .catch(() => {});
  }, []);

  return (
    <nav className="rail" aria-label="Sections">
      {items.map((item) => (
        <button
          key={item.view}
          type="button"
          aria-current={view === item.view ? "page" : undefined}
          onClick={() => setView(item.view)}
        >
          <span>{item.label}</span>
          {item.phase && <span className="phase">{item.phase}</span>}
        </button>
      ))}
      <div className="rail-foot">{version}</div>
    </nav>
  );
}
