import { useEffect, useState, type FormEvent } from "react";
import { open } from "@tauri-apps/plugin-dialog";

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
  const [path, setPath] = useState("");

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
      filters: [{ name: "Images", extensions: ["jpg", "jpeg", "png", "tif", "tiff", "heic", "webp", "dng", "cr2", "nef"] }],
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
        <button type="button" className="btn danger" disabled={!running} onClick={onCancel}>
          Cancel
        </button>
      </form>
      <p className="muted">
        Reads EXIF, GPS, camera, timestamps and hashes locally. The image never leaves this machine; reverse-image
        launchers open the search pages for you to drop the file into.
      </p>
    </>
  );
}
