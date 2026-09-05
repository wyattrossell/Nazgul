/** Username variants from a handle or a "First Last" name. */
export function usernameVariants(input: string, max = 40): string[] {
  const raw = input.trim().toLowerCase();
  if (!raw) return [];

  const tokens = raw.split(/[\s._-]+/).filter(Boolean);
  const out = new Set<string>();
  const add = (s: string) => {
    const v = s.replace(/[^a-z0-9._-]/g, "");
    if (v.length >= 3 && v !== raw) out.add(v);
  };

  const joined = tokens.join("");
  add(joined);
  if (tokens.length > 1) {
    const [first, ...rest] = tokens;
    const last = rest[rest.length - 1];
    add(tokens.join("."));
    add(tokens.join("_"));
    add(tokens.join("-"));
    add(`${first[0]}${last}`);
    add(`${first}${last[0]}`);
    add(`${first[0]}.${last}`);
    add(`${first[0]}_${last}`);
    add(`${last}${first}`);
    add(`${last}.${first}`);
    add(`${last}_${first}`);
    add(`${last}${first[0]}`);
  }

  const bases = [raw.replace(/[\s.-]+/g, ""), joined, ...(tokens.length > 1 ? [`${tokens[0]}_${tokens[tokens.length - 1]}`] : [])];
  for (const b of bases) {
    for (const suffix of ["1", "01", "123", "007", "99", "_", "x", "official", "real"]) add(`${b}${suffix}`);
    add(`the${b}`);
    add(`${b}_`);
    add(`_${b}`);
    add(`x${b}x`);
  }

  const leet = joined.replace(/o/g, "0").replace(/e/g, "3").replace(/a/g, "4").replace(/i/g, "1");
  add(leet);
  const digitsStripped = raw.replace(/\d+$/, "");
  add(digitsStripped);

  return [...out].slice(0, max);
}
