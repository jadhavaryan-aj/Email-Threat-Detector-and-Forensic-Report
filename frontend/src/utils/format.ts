/** Backend timestamps are serialized as naive ISO strings (no "Z"/offset) but the
 * values are always UTC (SQLite drops tzinfo on round-trip) — without this, `new
 * Date(...)` silently treats them as local time. */
export function formatTimestamp(isoString: string): string {
  const withZone = /[Zz]|[+-]\d{2}:?\d{2}$/.test(isoString) ? isoString : `${isoString}Z`;
  return new Date(withZone).toLocaleString();
}
