import { api, errorText } from "./api";
import type { ProbeKind, ScanOptions } from "./types";
import { effectiveProxy, useStore } from "../store";

export interface QueuedScan {
  probe: ProbeKind;
  input: string;
  patch?: Partial<ScanOptions>;
}

function baseOptions(): ScanOptions {
  const { settings } = useStore.getState();
  return {
    categories: [],
    includeNsfw: settings.includeNsfw,
    concurrency: settings.concurrency,
    timeoutSecs: settings.timeoutSecs,
    userAgent: settings.userAgent || null,
    proxy: effectiveProxy(settings),
    airgap: settings.airgap,
    rotateUserAgent: settings.rotateUa,
  };
}

/** Starts a scan and registers it in the store. Throws on validation errors from the backend. */
export async function launchScan(probe: ProbeKind, input: string, patch: Partial<ScanOptions> = {}): Promise<string> {
  const { settings, beginScan } = useStore.getState();
  const handle = await api.startScan({
    probe,
    input: input.trim(),
    caseId: settings.activeCaseId,
    options: { ...baseOptions(), ...patch },
  });
  beginScan(handle.scanId, handle.probe, handle.input, handle.caseId);
  return handle.scanId;
}

/** Starts the next queued scan when nothing is running. Called after every scan finishes. */
export async function drainQueue(): Promise<void> {
  const state = useStore.getState();
  const running = Object.values(state.scans).some((s) => s.status === "running");
  if (running) return;
  const next = state.dequeue();
  if (!next) return;
  try {
    await launchScan(next.probe, next.input, next.patch);
    state.pushLog("info", `queue: started ${next.probe} ${next.input} (${useStore.getState().queue.length} left)`);
  } catch (err) {
    state.pushLog("bad", `queue: ${next.input} failed to start: ${errorText(err)}`);
    void drainQueue();
  }
}

export function enqueueScans(items: QueuedScan[]): void {
  useStore.getState().enqueue(items);
  void drainQueue();
}
