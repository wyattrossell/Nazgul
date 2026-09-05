import { useEffect, useState, type FormEvent } from "react";

import { api, errorText, saveTextAs } from "../../lib/api";
import { buildCaseReport } from "../../lib/report";
import { safeFileStem } from "../../lib/export";
import { ENTITY_PROBE, probeMeta, type Entity, type Note } from "../../lib/types";
import { selectActiveCase, useStore } from "../../store";

function when(ms: number): string {
  return new Date(ms).toLocaleString([], { dateStyle: "short", timeStyle: "short" });
}

export function CasesPage() {
  const cases = useStore((s) => s.cases);
  const activeCase = useStore(selectActiveCase);
  const entities = useStore((s) => s.entities);
  const loadCases = useStore((s) => s.loadCases);
  const loadEntities = useStore((s) => s.loadEntities);
  const setActiveCase = useStore((s) => s.setActiveCase);
  const requestProbe = useStore((s) => s.requestProbe);
  const pushLog = useStore((s) => s.pushLog);

  const [newName, setNewName] = useState("");
  const [newDesc, setNewDesc] = useState("");
  const [renaming, setRenaming] = useState<{ id: number; name: string; description: string } | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<number | null>(null);
  const [notes, setNotes] = useState<Note[]>([]);
  const [noteDraft, setNoteDraft] = useState("");
  const [tagEdit, setTagEdit] = useState<{ id: number; value: string } | null>(null);
  const [manual, setManual] = useState({ type: "username", value: "" });

  const caseId = activeCase?.id ?? 0;

  const refreshNotes = async () => {
    if (!caseId) return;
    try {
      setNotes(await api.listNotes(caseId, null));
    } catch (err) {
      pushLog("bad", errorText(err));
    }
  };

  useEffect(() => {
    void loadCases();
    void loadEntities();
  }, [loadCases, loadEntities]);

  useEffect(() => {
    void refreshNotes();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [caseId]);

  const createCase = async (e: FormEvent) => {
    e.preventDefault();
    try {
      const created = await api.createCase(newName, newDesc);
      setNewName("");
      setNewDesc("");
      await loadCases();
      setActiveCase(created.id);
      pushLog("ok", `case "${created.name}" created`);
    } catch (err) {
      pushLog("bad", errorText(err));
    }
  };

  const saveRename = async () => {
    if (!renaming) return;
    try {
      await api.updateCase(renaming.id, renaming.name, renaming.description);
      setRenaming(null);
      await loadCases();
    } catch (err) {
      pushLog("bad", errorText(err));
    }
  };

  const remove = async (id: number) => {
    try {
      await api.deleteCase(id);
      setConfirmDelete(null);
      await loadCases();
      await loadEntities();
      pushLog("warn", `case ${id} deleted`);
    } catch (err) {
      pushLog("bad", errorText(err));
    }
  };

  const addNote = async () => {
    if (!noteDraft.trim() || !caseId) return;
    try {
      await api.addNote(caseId, null, noteDraft);
      setNoteDraft("");
      await refreshNotes();
    } catch (err) {
      pushLog("bad", errorText(err));
    }
  };

  const saveTags = async (entity: Entity, value: string) => {
    const tags = value
      .split(/[,\s]+/)
      .map((t) => t.trim())
      .filter(Boolean);
    try {
      await api.setEntityTags(entity.id, tags);
      setTagEdit(null);
      await loadEntities();
    } catch (err) {
      pushLog("bad", errorText(err));
    }
  };

  const addManual = async (e: FormEvent) => {
    e.preventDefault();
    if (!manual.value.trim() || !caseId) return;
    try {
      await api.addEntity(caseId, manual.type as Entity["type"], manual.value, null);
      setManual({ ...manual, value: "" });
      await loadEntities();
      await loadCases();
    } catch (err) {
      pushLog("bad", errorText(err));
    }
  };

  const exportReport = async () => {
    if (!activeCase) return;
    try {
      const [ents, scans, hits, caseNotes, info] = await Promise.all([
        api.listEntities(activeCase.id),
        api.listScans(activeCase.id, 1000),
        api.caseHits(activeCase.id),
        api.listNotes(activeCase.id, null),
        api.appInfo(),
      ]);
      const html = buildCaseReport({ caseInfo: activeCase, entities: ents, scans, hits, notes: caseNotes, version: info.version });
      const path = await saveTextAs(`nazgul-report-${safeFileStem(activeCase.name)}.html`, "html", html);
      if (path) pushLog("ok", `report saved: ${path}`);
    } catch (err) {
      pushLog("bad", `report failed: ${errorText(err)}`);
    }
  };

  const pivot = (entity: Entity) => {
    const probe = ENTITY_PROBE[entity.type];
    if (probe && probeMeta(probe).available) requestProbe(probe, entity.value);
  };

  return (
    <section className="page wide">
      <div className="row between">
        <h1>cases</h1>
        <button type="button" className="btn" onClick={exportReport} disabled={!activeCase} title="Self-contained HTML report for the active case (print to PDF from your browser)">
          Export report
        </button>
      </div>

      <div className="split">
        <div>
          <h2>All cases</h2>
          <div className="case-list">
            {cases.map((c) => (
              <div key={c.id} className="case" aria-current={c.id === caseId}>
                {renaming?.id === c.id ? (
                  <div className="case-edit">
                    <input
                      className="input"
                      value={renaming.name}
                      onChange={(e) => setRenaming({ ...renaming, name: e.target.value })}
                      aria-label="Case name"
                    />
                    <input
                      className="input"
                      value={renaming.description}
                      onChange={(e) => setRenaming({ ...renaming, description: e.target.value })}
                      placeholder="description"
                      aria-label="Case description"
                    />
                    <div className="row">
                      <button type="button" className="btn sm primary" onClick={saveRename}>
                        Save
                      </button>
                      <button type="button" className="btn sm" onClick={() => setRenaming(null)}>
                        Cancel
                      </button>
                    </div>
                  </div>
                ) : (
                  <>
                    <button type="button" className="case-main" onClick={() => setActiveCase(c.id)}>
                      <span className="name">{c.name}</span>
                      {c.description && <span className="desc">{c.description}</span>}
                      <span className="counts">
                        {c.entityCount} entities · {c.scanCount} scans · {c.findingCount} hits · {when(c.updatedAt)}
                      </span>
                    </button>
                    <div className="row">
                      <button
                        type="button"
                        className="btn sm"
                        onClick={() => setRenaming({ id: c.id, name: c.name, description: c.description })}
                      >
                        Edit
                      </button>
                      {confirmDelete === c.id ? (
                        <>
                          <button type="button" className="btn sm danger" onClick={() => remove(c.id)}>
                            Confirm delete
                          </button>
                          <button type="button" className="btn sm" onClick={() => setConfirmDelete(null)}>
                            Keep
                          </button>
                        </>
                      ) : (
                        <button type="button" className="btn sm" onClick={() => setConfirmDelete(c.id)}>
                          Delete
                        </button>
                      )}
                    </div>
                  </>
                )}
              </div>
            ))}
          </div>

          <h2>New case</h2>
          <form className="stack" onSubmit={createCase}>
            <input
              className="input"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              placeholder="case name"
              aria-label="New case name"
            />
            <input
              className="input"
              value={newDesc}
              onChange={(e) => setNewDesc(e.target.value)}
              placeholder="what this investigation is about"
              aria-label="New case description"
            />
            <div className="row">
              <button type="submit" className="btn primary" disabled={!newName.trim()}>
                Create case
              </button>
            </div>
          </form>

          <h2>Case notes</h2>
          <div className="stack">
            <textarea
              className="input"
              rows={3}
              value={noteDraft}
              onChange={(e) => setNoteDraft(e.target.value)}
              placeholder="observations, hypotheses, next steps"
              aria-label="New note"
            />
            <div className="row">
              <button type="button" className="btn" disabled={!noteDraft.trim()} onClick={addNote}>
                Add note
              </button>
            </div>
            {notes.map((n) => (
              <div key={n.id} className="note">
                <div className="note-body">{n.body}</div>
                <div className="note-meta">
                  {when(n.updatedAt)}
                  <button
                    type="button"
                    className="btn sm"
                    onClick={() => api.deleteNote(n.id).then(refreshNotes).catch((err) => pushLog("bad", errorText(err)))}
                  >
                    Delete
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div>
          <h2>Entities in {activeCase?.name ?? "…"}</h2>
          {entities.length === 0 ? (
            <p className="muted">No entities yet. Run a probe, or add one by hand below.</p>
          ) : (
            <div className="tbl-wrap">
              <table className="grid">
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>Value</th>
                    <th>Hits</th>
                    <th>Scans</th>
                    <th>Tags</th>
                    <th>Added</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {entities.map((e) => {
                    const probe = ENTITY_PROBE[e.type];
                    const canProbe = !!probe && probeMeta(probe).available;
                    return (
                      <tr key={e.id}>
                        <td>
                          <span className="chip static">{e.type}</span>
                        </td>
                        <td title={e.label ?? undefined}>{e.value}</td>
                        <td className="num">{e.foundCount}</td>
                        <td className="num">{e.scanCount}</td>
                        <td>
                          {tagEdit?.id === e.id ? (
                            <input
                              className="input sm"
                              autoFocus
                              value={tagEdit.value}
                              onChange={(ev) => setTagEdit({ id: e.id, value: ev.target.value })}
                              onBlur={() => saveTags(e, tagEdit.value)}
                              onKeyDown={(ev) => {
                                if (ev.key === "Enter") saveTags(e, tagEdit.value);
                                if (ev.key === "Escape") setTagEdit(null);
                              }}
                              aria-label="Tags"
                            />
                          ) : (
                            <button
                              type="button"
                              className="tags"
                              onClick={() => setTagEdit({ id: e.id, value: e.tags.join(" ") })}
                              title="Edit tags"
                            >
                              {e.tags.length ? e.tags.map((t) => `#${t}`).join(" ") : "+ tag"}
                            </button>
                          )}
                        </td>
                        <td className="num">{when(e.createdAt)}</td>
                        <td>
                          <div className="row">
                            <button type="button" className="btn sm" disabled={!canProbe} onClick={() => pivot(e)}>
                              Probe
                            </button>
                            <button
                              type="button"
                              className="btn sm"
                              onClick={() =>
                                api
                                  .deleteEntity(e.id)
                                  .then(() => Promise.all([loadEntities(), loadCases()]))
                                  .catch((err) => pushLog("bad", errorText(err)))
                              }
                            >
                              ×
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}

          <h2>Add entity by hand</h2>
          <form className="row" onSubmit={addManual}>
            <select
              className="input"
              style={{ width: 140 }}
              value={manual.type}
              onChange={(e) => setManual({ ...manual, type: e.target.value })}
              aria-label="Entity type"
            >
              {["username", "email", "phone", "domain", "ip", "wallet", "person", "org", "url"].map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
            <input
              className="input"
              value={manual.value}
              onChange={(e) => setManual({ ...manual, value: e.target.value })}
              placeholder="value"
              aria-label="Entity value"
            />
            <button type="submit" className="btn" disabled={!manual.value.trim()}>
              Add
            </button>
          </form>
        </div>
      </div>
    </section>
  );
}
