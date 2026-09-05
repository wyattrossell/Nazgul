import { useEffect, useState, type FormEvent } from "react";

import { api, errorText } from "../../../lib/api";
import type { PluginList } from "../../../lib/types";
import { useStore } from "../../../store";

interface Props {
  submitting: boolean;
  running: boolean;
  onRun: (input: string, plugin: string) => void;
  onCancel: () => void;
}

export function PluginForm({ submitting, running, onRun, onCancel }: Props) {
  const pendingInput = useStore((s) => s.pendingInput);
  const consumePendingInput = useStore((s) => s.consumePendingInput);
  const pushLog = useStore((s) => s.pushLog);
  const [list, setList] = useState<PluginList | null>(null);
  const [plugin, setPlugin] = useState("");
  const [value, setValue] = useState("");

  useEffect(() => {
    api
      .listPlugins()
      .then((l) => {
        setList(l);
        if (!plugin && l.plugins[0]) setPlugin(l.plugins[0].name);
      })
      .catch((e) => pushLog("bad", `plugins: ${errorText(e)}`));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (pendingInput !== null) {
      setValue(pendingInput);
      consumePendingInput();
    }
  }, [pendingInput, consumePendingInput]);

  const selected = list?.plugins.find((p) => p.name === plugin);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (plugin) onRun(value, plugin);
  };

  return (
    <>
      <form className="search-row" onSubmit={submit}>
        <select
          className="input"
          style={{ width: 220, flex: "none" }}
          value={plugin}
          onChange={(e) => setPlugin(e.target.value)}
          aria-label="Plugin"
          disabled={!list || list.plugins.length === 0}
        >
          {list?.plugins.map((p) => (
            <option key={p.name} value={p.name}>
              {p.name}
            </option>
          ))}
          {list && list.plugins.length === 0 && <option value="">no manifests found</option>}
        </select>
        <input
          className="input lg"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder={selected ? `${selected.inputTypes.join(" / ") || "input"} for ${selected.name}` : "input"}
          autoFocus
          spellCheck={false}
          aria-label="Plugin input"
        />
        <button type="submit" className="btn primary" disabled={submitting || !plugin || !value.trim()}>
          {submitting ? "Starting…" : "Run"}
        </button>
        <button type="button" className="btn danger" disabled={!running} onClick={onCancel}>
          Cancel
        </button>
      </form>
      {selected ? (
        <p className="muted">
          {selected.description} <span className="mono">{selected.command} {selected.args.join(" ")}</span>
        </p>
      ) : (
        <p className="muted">
          Drop a manifest JSON into {list?.dirs[0] ?? "the plugins folder"} to add a tool. See plugins/README.md for the
          format.
        </p>
      )}
    </>
  );
}
