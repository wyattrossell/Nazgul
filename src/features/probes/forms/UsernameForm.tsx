import { useEffect, useMemo, useState, type FormEvent } from "react";

import { api, errorText } from "../../../lib/api";
import { enqueueScans } from "../../../lib/scans";
import { NSFW_CATEGORY, type CategoryCount } from "../../../lib/types";
import { usernameVariants } from "../../../lib/variants";
import { useStore } from "../../../store";

interface Props {
  submitting: boolean;
  running: boolean;
  onRun: (input: string, categories: string[]) => void;
  onCancel: () => void;
}

export function UsernameForm({ submitting, running, onRun, onCancel }: Props) {
  const includeNsfw = useStore((s) => s.settings.includeNsfw);
  const pendingInput = useStore((s) => s.pendingInput);
  const consumePendingInput = useStore((s) => s.consumePendingInput);
  const pushLog = useStore((s) => s.pushLog);

  const [account, setAccount] = useState("");
  const [categories, setCategories] = useState<CategoryCount[]>([]);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [showVariants, setShowVariants] = useState(false);
  const [chosenVariants, setChosenVariants] = useState<Set<string>>(new Set());

  useEffect(() => {
    api
      .listSites()
      .then((summary) => setCategories(summary.categories))
      .catch((e) => pushLog("bad", `could not load site list: ${errorText(e)}`));
  }, [pushLog]);

  useEffect(() => {
    if (pendingInput !== null) {
      setAccount(pendingInput);
      consumePendingInput();
    }
  }, [pendingInput, consumePendingInput]);

  const visible = useMemo(
    () => categories.filter((c) => includeNsfw || c.name !== NSFW_CATEGORY),
    [categories, includeNsfw],
  );

  const siteCount = useMemo(() => {
    const chosen = picked.size ? visible.filter((c) => picked.has(c.name)) : visible;
    return chosen.reduce((n, c) => n + c.count, 0);
  }, [picked, visible]);

  const variants = useMemo(() => (showVariants ? usernameVariants(account) : []), [showVariants, account]);

  const toggle = (name: string) =>
    setPicked((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });

  const toggleVariant = (v: string) =>
    setChosenVariants((prev) => {
      const next = new Set(prev);
      if (next.has(v)) next.delete(v);
      else next.add(v);
      return next;
    });

  const submit = (e: FormEvent) => {
    e.preventDefault();
    onRun(account, [...picked]);
  };

  const queueVariants = () => {
    const list = [...chosenVariants];
    if (list.length === 0) return;
    enqueueScans(list.map((input) => ({ probe: "username" as const, input, patch: { categories: [...picked] } })));
    pushLog("info", `queued ${list.length} variant scan${list.length === 1 ? "" : "s"}`);
    setChosenVariants(new Set());
    setShowVariants(false);
  };

  return (
    <>
      <form className="search-row" onSubmit={submit}>
        <input
          className="input lg"
          value={account}
          onChange={(e) => setAccount(e.target.value)}
          placeholder="handle or full name, e.g. jdoe_dev or John Doe"
          autoFocus
          spellCheck={false}
          autoCapitalize="off"
          autoCorrect="off"
          aria-label="Username"
        />
        <button type="submit" className="btn primary" disabled={submitting}>
          {submitting ? "Starting…" : `Run ${siteCount} sites`}
        </button>
        <button
          type="button"
          className="btn"
          aria-pressed={showVariants}
          disabled={!account.trim()}
          onClick={() => setShowVariants((v) => !v)}
          title="Generate handle variants and queue them"
        >
          Variants
        </button>
        <button type="button" className="btn danger" disabled={!running} onClick={onCancel}>
          Cancel
        </button>
      </form>

      {showVariants && (
        <div className="variants">
          <div className="row between">
            <span className="label">
              {variants.length} variants of "{account.trim()}" · click to fill, tick to queue
            </span>
            <div className="row">
              <button type="button" className="btn sm" onClick={() => setChosenVariants(new Set(variants))}>
                Select all
              </button>
              <button type="button" className="btn sm primary" disabled={chosenVariants.size === 0} onClick={queueVariants}>
                Queue {chosenVariants.size || ""} scans
              </button>
            </div>
          </div>
          <div className="variant-grid">
            {variants.map((v) => (
              <span key={v} className="variant">
                <input
                  type="checkbox"
                  checked={chosenVariants.has(v)}
                  onChange={() => toggleVariant(v)}
                  aria-label={`Queue ${v}`}
                />
                <button type="button" onClick={() => setAccount(v)} title="Use this handle">
                  {v}
                </button>
              </span>
            ))}
          </div>
        </div>
      )}

      <div className="cat-row">
        <span className="label">categories</span>
        <button type="button" className="chip" aria-pressed={picked.size === 0} onClick={() => setPicked(new Set())}>
          all
        </button>
        {visible.map((c) => (
          <button
            key={c.name}
            type="button"
            className="chip"
            aria-pressed={picked.has(c.name)}
            onClick={() => toggle(c.name)}
            title={`${c.count} sites`}
          >
            {c.name === NSFW_CATEGORY ? "nsfw" : c.name} {c.count}
          </button>
        ))}
      </div>
    </>
  );
}
