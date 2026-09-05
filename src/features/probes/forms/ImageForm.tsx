import { useEffect, useState, type FormEvent } from "react";
import { open } from "@tauri-apps/plugin-dialog";

import { api, errorText } from "../../../lib/api";
import { useStore } from "../../../store";

interface Props {
  submitting: boolean;
  running: boolean;
  onRun: (input: string) => void;
  onCancel: () => void;
}

export function ImageForm({ submitting, running, onRun, onCancel }: Props) {
  const pendingInput = useStore((s) => s.pendingInput);
  const consumePendingInput = useStore((s) => s.consumePendingInput);
  const pushLog = useStore((s) => s.pushLog);
  const [path, setPath] = useState("");

  const flip = async () => {
    try {
      const out = await api.saveFlippedImage(path.trim());
      pushLog("ok", `flipped copy saved: ${out}`);
    } catch (err) {
      pushLog("bad", `flip failed: ${errorText(err)}`);
    }
  };

  useEffect(() => {
    if (pendingInput !== null) {
      setPath(pendingInput);
      consumePendingInput();
    }
  }, [pendingInput, consumePendingInput]);

  const pick = async () => {
    const chosen = await open({
      multiple: false,
      directory: false,
      filters: [
        { name: "Images and documents", extensions: ["jpg", "jpeg", "png", "tif", "tiff", "heic", "webp", "dng", "cr2", "nef", "gif", "bmp", "pdf", "docx", "xlsx", "pptx"] },
      ],
    });
    if (typeof chosen === "string") setPath(chosen);
  };

  const submit = (e: FormEvent) => {
    e.preventDefault();
    onRun(path);
  };

  return (
    <>
      <form className="search-row" onSubmit={submit}>
        <input
          className="input lg"
          value={path}
          onChange={(e) => setPath(e.target.value)}
          placeholder="C:\\path\\to\\photo.jpg"
          spellCheck={false}
          aria-label="Image path"
        />
        <button type="button" className="btn" onClick={pick}>
          Pick file…
        </button>
        <button type="submit" className="btn primary" disabled={submitting || !path.trim()}>
          {submitting ? "Starting…" : "Run"}
        </button>
        <button type="button" className="btn" disabled={!path.trim()} onClick={flip} title="Save a horizontally flipped copy next to the original. Run both through reverse-image search: a flip defeats many exact-match indexes.">
          Save flipped copy
        </button>
        <button type="button" className="btn danger" disabled={!running} onClick={onCancel}>
          Cancel
        </button>
      </form>
      <p className="muted">
        Reads EXIF, GPS, camera, timestamps, PDF and Office metadata and hashes locally. The file never leaves this
        machine; reverse-image launchers open the search pages for you to drop the file into. Never upload contraband
        imagery to any online service.
      </p>
    </>
  );
}
