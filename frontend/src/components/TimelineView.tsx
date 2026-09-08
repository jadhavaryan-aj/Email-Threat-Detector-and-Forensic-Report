import type { TimelineEvent } from "../types/case";
import { formatTimestamp } from "../utils/format";
import { titleCase } from "../utils/severityColors";

export function TimelineView({ events }: { events: TimelineEvent[] }) {
  if (events.length === 0) {
    return <p className="text-sm text-zinc-500">No timeline events recorded yet.</p>;
  }

  return (
    <ol className="relative ml-2 space-y-4 border-l border-zinc-800 pl-5">
      {events.map((event) => (
        <li key={event.id} className="relative">
          <span className="absolute top-1 -left-[25px] h-2.5 w-2.5 rounded-full border-2 border-zinc-950 bg-cyan-500" />
          <p className="text-sm font-medium text-zinc-200">{titleCase(event.event_type)}</p>
          <p className="text-xs text-zinc-400">{event.description}</p>
          <p className="text-[11px] text-zinc-600">{formatTimestamp(event.occurred_at)}</p>
        </li>
      ))}
    </ol>
  );
}
