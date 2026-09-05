import { useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";

import { api, errorText } from "../lib/api";
import { useStore } from "../store";

export function UpdateBanner() {
  const update = useStore((s) => s.update);
  const setUpdate = useStore((s) => s.setUpdate);
  const pushLog = useStore((s) => s.pushLog);
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<{ downloaded: number; total: number | null } | null>(null);
  const [dismissed, setDismissed] = useState(false);

  useEffect(() => {
    let dispose: (() => void) | undefined;
    listen<{ downloaded: number; total: number | null }>("update://progress", (e) => setProgress(e.payload)).then((fn) => {
      dispose = fn;
    });
    return () => dispose?.();
  }, []);

  if (!update?.available || dismissed) return null;

  const install = async () => {
    setBusy(true);
    pushLog("info", `downloading Nazgul v${update.version}…`);
    try {
      await api.installUpdate();
    } catch (err) {
      setBusy(false);
      pushLog("bad", `update failed: ${errorText(err)}`);
    }
  };

  const pct = progress && progress.total ? Math.min(100, Math.round((progress.downloaded / progress.total) * 100)) : null;

  return (
    <div className="update-banner" role="status">
      <span className="mono">
        <b>v{update.version}</b> is available (you have v{update.current}).
        {update.notes && <span className="muted"> {update.notes.slice(0, 140)}</span>}
      </span>
      <span className="spacer" />
      {busy ? (
        <span className="mono">{pct !== null ? `downloading ${pct}%` : "downloading…"}</span>
      ) : (
        <>
          <button type="button" className="btn sm primary" onClick={install}>
            Install and restart
          </button>
          <button type="button" className="btn sm" onClick={() => { setDismissed(true); setUpdate({ ...update, available: false }); }}>
            Later
          </button>
        </>
      )}
    </div>
  );
}
