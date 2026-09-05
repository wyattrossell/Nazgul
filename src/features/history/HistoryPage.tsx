import { useEffect, useState } from "react";

import { api, errorText } from "../../lib/api";
import { selectActiveCase, useStore } from "../../store";

function when(ms: number): string {
  return new Date(ms).toLocaleString([], { dateStyle: "short", timeStyle: "medium" });
}

export function HistoryPage() {
  const history = useStore((s) => s.history);
  const loadHistory = useStore((s) => s.loadHistory);
  const openHistoricScan = useStore((s) => s.openHistoricScan);
  const loadCases = useStore((s) => s.loadCases);
  const activeCase = useStore(selectActiveCase);
  const pushLog = useStore((s) => s.pushLog);
  const [allCases, setAllCases] = useState(false);

  useEffect(() => {
    void loadHistory(allCases);
  }, [allCases, loadHistory, activeCase?.id]);

  const remove = async (id: string) => {
    try {
      await api.deleteScan(id);
      await loadHistory(allCases);
      await loadCases();
    } catch (err) {
      pushLog("bad", errorText(err));
    }
  };

  return (
    <section className="page wide">
      <div className="row between">
        <h1>history</h1>
        <div className="seg" role="group" aria-label="Scope">
          <button type="button" aria-pressed={!allCases} onClick={() => setAllCases(false)}>
            {activeCase?.name ?? "this case"}
          </button>
          <button type="button" aria-pressed={allCases} onClick={() => setAllCases(true)}>
            all cases
          </button>
        </div>
      </div>
      <p className="muted">Every query is logged with its time, scope and outcome. Open one to bring its results back.</p>

      {history.length === 0 ? (
        <p className="muted">No scans recorded yet.</p>
      ) : (
        <div className="tbl-wrap">
          <table className="grid">
            <thead>
              <tr>
                <th>When</th>
                {allCases && <th>Case</th>}
                <th>Probe</th>
                <th>Input</th>
                <th>Status</th>
                <th>Hits</th>
                <th>Checked</th>
                <th>Time</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {history.map((row) => (
                <tr key={row.id} onDoubleClick={() => openHistoricScan(row)}>
                  <td className="num">{when(row.startedAt)}</td>
                  {allCases && <td>{row.caseName}</td>}
                  <td>
                    <span className="chip static">{row.probe}</span>
                  </td>
                  <td title={row.input}>{row.input}</td>
                  <td>
                    <span className={`status ${row.status === "done" ? "found" : row.status === "running" ? "info" : row.status === "error" ? "error" : "ambiguous"}`}>
                      {row.status}
                    </span>
                    {row.error && <span className="muted"> {row.error}</span>}
                  </td>
                  <td className="num">{row.found}</td>
                  <td className="num">
                    {row.checked}/{row.total}
                  </td>
                  <td className="num">{row.elapsedMs !== null ? `${(row.elapsedMs / 1000).toFixed(1)}s` : "—"}</td>
                  <td>
                    <div className="row">
                      <button type="button" className="btn sm" onClick={() => openHistoricScan(row)}>
                        Open
                      </button>
                      <button type="button" className="btn sm" onClick={() => remove(row.id)} title="Delete this scan and its findings">
                        ×
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
