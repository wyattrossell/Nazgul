import { useEffect, useState } from "react";

import { api, errorText } from "../../lib/api";
import { launchScan } from "../../lib/scans";
import { PROBES, probeMeta, type ProbeKind, type ScanOptions } from "../../lib/types";
import { selectActiveScan, useStore } from "../../store";
import { Results } from "./Results";
import { BatchPanel } from "./BatchPanel";
import { UsernameForm } from "./forms/UsernameForm";
import { PhoneForm } from "./forms/PhoneForm";
import { ImageForm } from "./forms/ImageForm";
import { PluginForm } from "./forms/PluginForm";
import { TextForm } from "./forms/TextForm";

export function ProbeView() {
  const probe = useStore((s) => s.probe);
  const setProbe = useStore((s) => s.setProbe);
  const scans = useStore((s) => s.scans);
  const scanOrder = useStore((s) => s.scanOrder);
  const active = useStore(selectActiveScan);
  const setActiveScan = useStore((s) => s.setActiveScan);
  const closeScan = useStore((s) => s.closeScan);
  const queue = useStore((s) => s.queue);
  const clearQueue = useStore((s) => s.clearQueue);
  const markCancelling = useStore((s) => s.markCancelling);
  const pushLog = useStore((s) => s.pushLog);

  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [batch, setBatch] = useState(false);

  useEffect(() => setError(null), [probe]);

  const launch = async (kind: ProbeKind, input: string, patch: Partial<ScanOptions> = {}) => {
    const value = input.trim();
    if (!value) {
      setError(`Enter ${probeMeta(kind).placeholder}.`);
      return;
    }
    setError(null);
    setSubmitting(true);
    try {
      await launchScan(kind, value, patch);
    } catch (err) {
      const text = errorText(err);
      setError(text);
      pushLog("bad", text);
    } finally {
      setSubmitting(false);
    }
  };

  const cancel = async () => {
    if (!active) return;
    const wasRunning = await api.cancelScan(active.id);
    if (wasRunning) {
      markCancelling(active.id);
      pushLog("warn", `cancelling scan ${active.id.slice(-4)}`);
    }
  };

  const isRunning = active?.status === "running";
  const progress = active && active.total > 0 ? Math.min(100, (active.checked / active.total) * 100) : 0;
  const meta = probeMeta(probe);

  return (
    <>
      <div className="probe-head">
        <div className="ptabs" role="tablist" aria-label="Probes">
          {PROBES.map((p) => (
            <button
              key={p.kind}
              type="button"
              role="tab"
              aria-selected={probe === p.kind}
              className={p.available ? undefined : "soon"}
              title={p.available ? p.blurb : `${p.blurb} (coming in a later phase)`}
              onClick={() => setProbe(p.kind)}
            >
              {p.label}
            </button>
          ))}
        </div>

        <div className="row between">
          <h1>
            {meta.label.toLowerCase()} probe<span className="cursor" aria-hidden="true" />
          </h1>
          <button type="button" className="btn sm" aria-pressed={batch} onClick={() => setBatch((v) => !v)} title="Paste a list of identifiers and queue them all">
            Batch
          </button>
        </div>
        {batch && <BatchPanel onClose={() => setBatch(false)} />}

        {probe === "username" ? (
          <UsernameForm
            submitting={submitting}
            running={isRunning}
            onRun={(input, categories) => launch("username", input, { categories })}
            onCancel={cancel}
          />
        ) : probe === "phone" ? (
          <PhoneForm
            submitting={submitting}
            running={isRunning}
            onRun={(input, region) => launch("phone", input, { extra: { region } })}
            onCancel={cancel}
          />
        ) : probe === "plugin" ? (
          <PluginForm
            submitting={submitting}
            running={isRunning}
            onRun={(input, plugin) => launch("plugin", input, { extra: { plugin } })}
            onCancel={cancel}
          />
        ) : probe === "image" ? (
          <ImageForm
            submitting={submitting}
            running={isRunning}
            onRun={(input) => launch("image", input)}
            onCancel={cancel}
          />
        ) : (
          <TextForm
            probe={probe}
            submitting={submitting}
            running={isRunning}
            onRun={(input) => launch(probe, input)}
            onCancel={cancel}
          />
        )}
        {error && <div className="status error">{error}</div>}
        {queue.length > 0 && (
          <div className="row queue-row">
            <span className="label">queued</span>
            <span className="mono">{queue.length} scan{queue.length === 1 ? "" : "s"} waiting · next: {queue[0].probe} {queue[0].input}</span>
            <button type="button" className="btn sm" onClick={clearQueue}>
              Clear queue
            </button>
          </div>
        )}

        {scanOrder.length > 0 && (
          <div className="scan-tabs" role="tablist" aria-label="Scans">
            {scanOrder.map((id) => {
              const scan = scans[id];
              return (
                <span key={id} className="scan-tab" aria-current={active?.id === id}>
                  <button type="button" role="tab" onClick={() => setActiveScan(id)}>
                    <span className="p">{scan.probe}</span>
                    <span>{scan.input}</span>
                    <span className="n">{scan.found}</span>
                    <span>{scan.status === "running" ? `${scan.checked}/${scan.total}` : scan.status}</span>
                  </button>
                  {scan.status !== "running" && (
                    <button type="button" className="x" title="Close tab" onClick={() => closeScan(id)}>
                      ×
                    </button>
                  )}
                </span>
              );
            })}
          </div>
        )}
      </div>

      <div className="progress" aria-hidden="true">
        <i style={{ width: `${progress}%`, opacity: isRunning || progress > 0 ? 1 : 0 }} />
      </div>

      <Results scan={active} />
    </>
  );
}
