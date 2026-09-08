import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { addCaseNote, getCaseNotes } from "../api/cases";
import { formatTimestamp } from "../utils/format";

export function CaseNotesPanel({ caseId }: { caseId: number }) {
  const [draft, setDraft] = useState("");
  const queryClient = useQueryClient();

  const { data: notes } = useQuery({ queryKey: ["case-notes", caseId], queryFn: () => getCaseNotes(caseId) });

  const mutation = useMutation({
    mutationFn: () => addCaseNote(caseId, draft),
    onSuccess: () => {
      setDraft("");
      queryClient.invalidateQueries({ queryKey: ["case-notes", caseId] });
      queryClient.invalidateQueries({ queryKey: ["case-timeline", caseId] });
    },
  });

  return (
    <div className="space-y-3">
      <div className="space-y-2">
        {(notes ?? []).map((note) => (
          <div key={note.id} className="rounded-md border border-zinc-800 bg-zinc-900/40 p-2.5">
            <div className="mb-1 flex items-center justify-between text-[11px] text-zinc-500">
              <span>{note.author}</span>
              <span>{formatTimestamp(note.created_at)}</span>
            </div>
            <p className="text-sm text-zinc-200">{note.note_text}</p>
          </div>
        ))}
        {notes && notes.length === 0 && <p className="text-sm text-zinc-500">No analyst notes yet.</p>}
      </div>
      <div className="flex gap-2">
        <textarea
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          placeholder="Add an investigation note…"
          rows={2}
          className="flex-1 rounded-md border border-zinc-700 bg-zinc-950 px-2.5 py-1.5 text-sm text-zinc-100 placeholder-zinc-600 focus:border-cyan-600 focus:outline-none"
        />
        <button
          type="button"
          disabled={!draft.trim() || mutation.isPending}
          onClick={() => mutation.mutate()}
          className="self-end rounded-md bg-cyan-600 px-3 py-1.5 text-sm font-medium text-white transition hover:bg-cyan-500 disabled:opacity-40"
        >
          Add
        </button>
      </div>
    </div>
  );
}
