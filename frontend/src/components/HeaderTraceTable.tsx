import type { ReceivedHop } from "../types/case";
import { formatTimestamp } from "../utils/format";

export function HeaderTraceTable({ hops }: { hops: ReceivedHop[] }) {
  if (hops.length === 0) {
    return <p className="text-sm text-zinc-500">No Received headers found.</p>;
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-zinc-800">
      <table className="min-w-full divide-y divide-zinc-800 text-sm">
        <thead className="bg-zinc-900">
          <tr>
            <th className="px-3 py-2 text-left font-medium text-zinc-400">#</th>
            <th className="px-3 py-2 text-left font-medium text-zinc-400">From host</th>
            <th className="px-3 py-2 text-left font-medium text-zinc-400">IP</th>
            <th className="px-3 py-2 text-left font-medium text-zinc-400">By host</th>
            <th className="px-3 py-2 text-left font-medium text-zinc-400">Timestamp</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-zinc-800 bg-zinc-950">
          {hops.map((hop) => (
            <tr key={hop.hop_index}>
              <td className="px-3 py-2 text-zinc-500">{hop.hop_index}</td>
              <td className="px-3 py-2 font-mono text-xs text-zinc-300">{hop.from_host ?? "—"}</td>
              <td className="px-3 py-2 font-mono text-xs text-zinc-300">{hop.ip ?? "—"}</td>
              <td className="px-3 py-2 font-mono text-xs text-zinc-300">{hop.by_host ?? "—"}</td>
              <td className="px-3 py-2 text-zinc-500">{hop.timestamp ? formatTimestamp(hop.timestamp) : "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
