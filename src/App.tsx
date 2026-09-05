import { useCallback, useEffect, useState } from "react";

import { api, errorText, listenToScans } from "./lib/api";
import { drainQueue } from "./lib/scans";
import { effectiveProxy, useStore, type View } from "./store";
import { BootSplash } from "./components/BootSplash";
import { UpdateBanner } from "./components/UpdateBanner";
import { TopBar } from "./components/TopBar";
import { Rail } from "./components/Rail";
import { Inspector } from "./components/Inspector";
import { LogStrip } from "./components/LogStrip";
import { ProbeView } from "./features/probes/ProbeView";
import { CasesPage } from "./features/cases/CasesPage";
import { HistoryPage } from "./features/history/HistoryPage";
import { SettingsPage } from "./features/settings/SettingsPage";
import { ToolboxPage } from "./features/toolbox/ToolboxPage";
import { GraphPage } from "./features/graph/GraphPage";

const VIEW_KEYS: Record<string, View> = { "1": "probes", "2": "cases", "3": "graph", "4": "history", "5": "toolbox", "6": "settings" };

export default function App() {
  const settings = useStore((s) => s.settings);
  const view = useStore((s) => s.view);
  const setView = useStore((s) => s.setView);
  const select = useStore((s) => s.select);
  const [booting, setBooting] = useState(() => useStore.getState().settings.splash);
  const finishBoot = useCallback(() => setBooting(false), []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.ctrlKey && !e.shiftKey && !e.altKey && VIEW_KEYS[e.key]) {
        e.preventDefault();
        setView(VIEW_KEYS[e.key]);
      } else if (e.key === "Escape") {
        select(null);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [setView, select]);

  useEffect(() => {
    const root = document.documentElement;
    root.setAttribute("data-skin", settings.skin);
    root.setAttribute("data-crt", settings.crt ? "on" : "off");
  }, [settings.skin, settings.crt]);

  useEffect(() => {
    let dispose: (() => void) | undefined;
    let cancelled = false;
    const { onScanStarted, onFinding, onScanDone, pushLog, loadCases, loadEntities } = useStore.getState();

    listenToScans({
      onStarted: (e) => {
        onScanStarted(e);
        pushLog("info", `${e.probe} ${e.scanId.slice(-4)} · ${e.input} · ${e.total} checks queued`);
      },
      onFinding: (f) => {
        onFinding(f);
        if (f.status === "found") pushLog("ok", `FOUND  ${f.source}  ${f.url ?? f.title}`);
        else if (f.status === "error") pushLog("bad", `ERROR  ${f.source}  ${f.detail ?? ""}`);
        for (const d of f.discovered) pushLog("info", `PIVOT  ${d.type} ${d.value} (via ${f.source})`);
      },
      onDone: (e) => {
        onScanDone(e);
        const secs = (e.elapsedMs / 1000).toFixed(1);
        if (e.error) pushLog("bad", `scan ${e.scanId.slice(-4)} failed: ${e.error}`);
        else
          pushLog(
            e.cancelled ? "warn" : "info",
            `scan ${e.scanId.slice(-4)} ${e.cancelled ? "cancelled" : "done"} · ${e.checked}/${e.total} checked · ${e.found} found · ${secs}s`,
          );
        void loadEntities();
        void loadCases();
        void drainQueue();
      },
    }).then((fn) => {
      if (cancelled) fn();
      else dispose = fn;
    });

    void loadCases().then(loadEntities);

    // Launch-time update check, unless the user is airgapped.
    const { settings: current, setUpdate } = useStore.getState();
    if (!current.airgap) {
      window.setTimeout(() => {
        api
          .checkUpdate()
          .then((info) => {
            setUpdate(info);
            if (info.available) pushLog("ok", `update available: v${info.version} (running v${info.current})`);
            else if (info.error) pushLog("warn", `update check: ${info.error}`);
            else pushLog("info", `v${info.current} is the latest release`);
          })
          .catch((err) => pushLog("warn", `update check failed: ${errorText(err)}`));
      }, 2500);
    }

    return () => {
      cancelled = true;
      dispose?.();
    };
  }, []);

  const routeLabel = settings.airgap ? "AIRGAP" : settings.route === "tor" ? "TOR" : effectiveProxy(settings) ? "PROXY" : "DIRECT";

  return (
    <div className="shell">
      {booting && <BootSplash route={routeLabel} onDone={finishBoot} />}
      <TopBar />
      <UpdateBanner />
      <Rail />
      <main className="main">
        {view === "probes" && <ProbeView />}
        {view === "cases" && <CasesPage />}
        {view === "history" && <HistoryPage />}
        {view === "settings" && <SettingsPage />}
        {view === "toolbox" && <ToolboxPage />}
        {view === "graph" && <GraphPage />}
      </main>
      <Inspector />
      <LogStrip />
    </div>
  );
}
