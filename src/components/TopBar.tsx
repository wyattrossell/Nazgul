import { useEffect, useState } from "react";

import { effectiveProxy, selectActiveCase, selectRunningCount, useStore } from "../store";

function clock(): string {
  return new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function TopBar() {
  const running = useStore(selectRunningCount);
  const settings = useStore((s) => s.settings);
  const route = settings.airgap
    ? "AIRGAP"
    : settings.route === "tor"
      ? "TOR"
      : effectiveProxy(settings)
        ? "PROXY"
        : "DIRECT";
  const activeCase = useStore(selectActiveCase);
  const setView = useStore((s) => s.setView);
  const [time, setTime] = useState(clock);

  useEffect(() => {
    const id = window.setInterval(() => setTime(clock()), 1000);
    return () => window.clearInterval(id);
  }, []);

  return (
    <header className="topbar">
      <span className="brand">NAZGUL</span>
      <button type="button" className="kv linkish" onClick={() => setView("cases")} title="Switch case">
        case <b>{activeCase?.name ?? "…"}</b>
      </button>
      <span className="kv">
        probes <b className={running > 0 ? "live" : undefined}>{running} running</b>
      </span>
      <button type="button" className="kv linkish" onClick={() => setView("settings")} title="Route settings">
        route <b className={route === "AIRGAP" ? "warn" : route === "TOR" ? "live" : undefined}>{route}</b>
      </button>
      <span className="spacer" />
      <span className="kv">
        <b>{time}</b>
      </span>
    </header>
  );
}
