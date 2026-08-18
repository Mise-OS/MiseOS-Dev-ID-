import canonicalize from "canonicalize";
export { canonicalize };
export function parseCanonical(json: string): unknown {
  const parsed = JSON.parse(json);
  const canonical = canonicalize(parsed);
  if (canonical !== json) throw new Error("Input is not canonical RFC 8785 JSON");
  return parsed;
}
