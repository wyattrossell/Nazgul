import { useEffect, useState, type FormEvent } from "react";

import { probeMeta, type ProbeKind } from "../../../lib/types";
import { useStore } from "../../../store";

interface Props {
  probe: ProbeKind;
  submitting: boolean;
  running: boolean;
  onRun: (input: string) => void;
  onCancel: () => void;
}

/** Single-input form used by every probe that takes one identifier. */
export function TextForm({ probe, submitting, running, onRun, onCancel }: Props) {
  const meta = probeMeta(probe);
  const pendingInput = useStore((s) => s.pendingInput);
  const consumePendingInput = useStore((s) => s.consumePendingInput);
  const [value, setValue] = useState("");

  useEffect(() => {
    if (pendingInput !== null) {
      setValue(pendingInput);
      consumePendingInput();
    }
  }, [pendingInput, consumePendingInput]);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    onRun(value);
  };

  return (
    <>
      <form className="search-row" onSubmit={submit}>
        <input
          className="input lg"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder={meta.placeholder}
          autoFocus
          spellCheck={false}
          autoCapitalize="off"
          autoCorrect="off"
          aria-label={meta.label}
          disabled={!meta.available}
        />
        <button type="submit" className="btn primary" disabled={submitting || !meta.available}>
          {submitting ? "Starting…" : "Run"}
        </button>
        <button type="button" className="btn danger" disabled={!running} onClick={onCancel}>
          Cancel
        </button>
      </form>
      <p className="muted">{meta.available ? meta.blurb : `${meta.blurb} Coming in a later phase.`}</p>
    </>
  );
}
