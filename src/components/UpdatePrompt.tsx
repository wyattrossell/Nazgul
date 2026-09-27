import { useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";

import { api, errorText } from "../lib/api";
import { useStore } from "../store";

interface Progress {
  downloaded: number;
  total: number | null;
}

function mb(bytes: number): string {
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

/**
 * Launch-time update prompt. When the GitHub check finds a newer signed release this
 * dialog asks the user to update now or wait. "Later" hides it for the rest of the
 * session; the next launch asks again, and Settings keeps an install button meanwhile.
 */
export function UpdatePrompt() {
  const update = useStore((s) => s.update);
  const pushLog = useStore((s) => s.pushLog);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState<Progress | null>(null);
  const [dismissedVersion, setDismissedVersion] = useState<string | null>(null);

  useEffect(() => {
    let dispose: (() => void) | undefined;
    listen<Progress>("update://progress", (e) => setProgress(e.payload)).then((fn) => {
      dispose = fn;
    });
    return () => dispose?.();
  }, []);

  const visible = !!update?.available && update.version !== dismissedVersion;

  useEffect(() => {
    if (!visible || busy) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") later();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [visible, busy, update?.version]);

  if (!visible || !update) return null;

  const later = () => {
    setDismissedVersion(update.version);
    pushLog("info", `update to v${update.version} postponed; Settings > Updates installs it any time`);
  };

  const install = async () => {
    setBusy(true);
    setError(null);
    setProgress(null);
    pushLog("info", `downloading Nazgul v${update.version}…`);
    try {
      await api.installUpdate();
    } catch (err) {
      const text = errorText(err);
      setBusy(false);
      setError(text);
      pushLog("bad", `update failed: ${text}`);
    }
  };

  const pct = progress && progress.total ? Math.min(100, Math.round((progress.downloaded / progress.total) * 100)) : null;
  const date = update.date ? update.date.slice(0, 10) : null;
  const notes = update.notes?.trim();

  return (
    <div className="update-prompt-backdrop" role="presentation">
      <div className="update-prompt" role="dialog" aria-modal="true" aria-labelledby="update-prompt-title">
        <div className="update-prompt-head">
          <span className="label">Update available</span>
          <h2 id="update-prompt-title" className="mono">
            Nazgul <b>v{update.version}</b>
          </h2>
          <span className="mono muted">
            you are running v{update.current}
            {date && ` · released ${date}`}
          </span>
        </div>

        {notes && <pre className="update-prompt-notes">{notes}</pre>}

        <p className="update-prompt-text muted">
          The installer is downloaded from the GitHub release, its signature is verified against the key built into this app,
          and Nazgul restarts when it finishes. Open cases are saved on disk and will still be there.
        </p>

        {error && <div className="update-prompt-error mono">{error}</div>}

        {busy ? (
          <div className="update-prompt-progress">
            <div className="update-prompt-bar" aria-hidden="true">
              <span style={{ width: pct !== null ? `${pct}%` : "100%" }} className={pct === null ? "indeterminate" : ""} />
            </div>
            <span className="mono muted">
              {pct !== null
                ? `downloading ${pct}% (${mb(progress!.downloaded)} of ${mb(progress!.total!)})`
                : progress
                  ? `downloading ${mb(progress.downloaded)}…`
                  : "connecting to GitHub…"}
            </span>
          </div>
        ) : (
          <div className="update-prompt-actions">
            <button type="button" className="btn primary" onClick={install} autoFocus>
              {error ? "Try again" : "Update now"}
            </button>
            <button type="button" className="btn" onClick={later}>
              Later
            </button>
            <span className="mono muted spacer">asks again on next launch</span>
          </div>
        )}
      </div>
    </div>
  );
}
