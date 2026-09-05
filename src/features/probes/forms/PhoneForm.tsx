import { useEffect, useState, type FormEvent } from "react";

import { useStore } from "../../../store";

const REGIONS: [string, string][] = [
  ["US", "United States +1"],
  ["CA", "Canada +1"],
  ["GB", "United Kingdom +44"],
  ["IE", "Ireland +353"],
  ["AU", "Australia +61"],
  ["NZ", "New Zealand +64"],
  ["DE", "Germany +49"],
  ["FR", "France +33"],
  ["ES", "Spain +34"],
  ["IT", "Italy +39"],
  ["NL", "Netherlands +31"],
  ["BE", "Belgium +32"],
  ["CH", "Switzerland +41"],
  ["SE", "Sweden +46"],
  ["NO", "Norway +47"],
  ["DK", "Denmark +45"],
  ["PL", "Poland +48"],
  ["PT", "Portugal +351"],
  ["BR", "Brazil +55"],
  ["MX", "Mexico +52"],
  ["AR", "Argentina +54"],
  ["IN", "India +91"],
  ["PK", "Pakistan +92"],
  ["JP", "Japan +81"],
  ["KR", "South Korea +82"],
  ["CN", "China +86"],
  ["HK", "Hong Kong +852"],
  ["SG", "Singapore +65"],
  ["PH", "Philippines +63"],
  ["ID", "Indonesia +62"],
  ["ZA", "South Africa +27"],
  ["NG", "Nigeria +234"],
  ["AE", "UAE +971"],
  ["IL", "Israel +972"],
  ["TR", "Türkiye +90"],
  ["RU", "Russia +7"],
  ["UA", "Ukraine +380"],
];

interface Props {
  submitting: boolean;
  running: boolean;
  onRun: (input: string, region: string) => void;
  onCancel: () => void;
}

export function PhoneForm({ submitting, running, onRun, onCancel }: Props) {
  const pendingInput = useStore((s) => s.pendingInput);
  const consumePendingInput = useStore((s) => s.consumePendingInput);
  const [value, setValue] = useState("");
  const [region, setRegion] = useState("US");

  useEffect(() => {
    if (pendingInput !== null) {
      setValue(pendingInput);
      consumePendingInput();
    }
  }, [pendingInput, consumePendingInput]);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    onRun(value, region);
  };

  return (
    <>
      <form className="search-row" onSubmit={submit}>
        <select
          className="input"
          style={{ width: 210, flex: "none" }}
          value={region}
          onChange={(e) => setRegion(e.target.value)}
          aria-label="Default region for numbers without a country code"
          title="Region assumed when the number has no + country code"
        >
          {REGIONS.map(([code, label]) => (
            <option key={code} value={code}>
              {label}
            </option>
          ))}
        </select>
        <input
          className="input lg"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder="+1 415 555 0100 or a national number"
          autoFocus
          spellCheck={false}
          aria-label="Phone number"
        />
        <button type="submit" className="btn primary" disabled={submitting}>
          {submitting ? "Starting…" : "Run"}
        </button>
        <button type="button" className="btn danger" disabled={!running} onClick={onCancel}>
          Cancel
        </button>
      </form>
      <p className="muted">
        Parses the number locally (country, line type, every format) and builds reverse-lookup and messaging links. Nothing
        is sent to the number.
      </p>
    </>
  );
}
