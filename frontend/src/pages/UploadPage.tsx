import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { uploadEmail } from "../api/cases";

interface UploadOutcome {
  name: string;
  status: "ok" | "error";
  message: string;
}

export function UploadPage() {
  const [files, setFiles] = useState<File[]>([]);
  const [results, setResults] = useState<UploadOutcome[]>([]);
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: async (fileList: File[]) => {
      const outcomes: UploadOutcome[] = [];
      let lastCaseId: number | null = null;
      for (const file of fileList) {
        try {
          const res = await uploadEmail(file);
          outcomes.push({ name: file.name, status: "ok", message: `analyzed → case #${res.case_id}` });
          lastCaseId = res.case_id;
        } catch (err: unknown) {
          const axiosErr = err as { response?: { data?: { detail?: string } }; message?: string };
          const detail = axiosErr?.response?.data?.detail;
          const message = typeof detail === "string" ? detail : (axiosErr?.message || "upload failed");
          outcomes.push({ name: file.name, status: "error", message });
        }
      }
      return { outcomes, lastCaseId };
    },
    onSuccess: ({ outcomes, lastCaseId }) => {
      setResults(outcomes);
      queryClient.invalidateQueries({ queryKey: ["cases"] });
      queryClient.invalidateQueries({ queryKey: ["dashboard-stats"] });
      if (lastCaseId !== null && outcomes.every((o) => o.status === "ok")) {
        setTimeout(() => navigate(`/cases/${lastCaseId}`), 900);
      }
    },
  });

  function handleFiles(list: FileList | null) {
    if (!list) return;
    setResults([]);
    const valid = Array.from(list).filter((f) => f.name.toLowerCase().endsWith(".eml"));
    if (valid.length < list.length) {
      setResults([
        {
          name: "Invalid format",
          status: "error",
          message: "Only .eml files are supported. Non-.eml files were filtered out.",
        },
      ]);
    }
    setFiles(valid);
  }

  return (
    <div className="mx-auto max-w-2xl">
      <h1 className="mb-1 text-xl font-semibold text-zinc-100">Upload email for analysis</h1>
      <p className="mb-6 text-sm text-zinc-500">
        Upload one or more raw <code className="text-zinc-400">.eml</code> files. Each is run through real
        SPF/DKIM/DMARC validation, header forensics, URL/domain/IP intelligence, and explainable signal-based
        scoring — no mocked results.
      </p>

      <label
        onDragOver={(e) => e.preventDefault()}
        onDrop={(e) => {
          e.preventDefault();
          handleFiles(e.dataTransfer.files);
        }}
        className="flex cursor-pointer flex-col items-center justify-center rounded-lg border-2 border-dashed border-zinc-700 bg-zinc-900/40 px-6 py-10 text-center transition hover:border-cyan-700 hover:bg-zinc-900"
      >
        <span className="text-sm font-medium text-zinc-300">Drop .eml files here, or click to browse</span>
        <span className="mt-1 text-xs text-zinc-600">
          Try the fixtures in <code>sample_emails/</code>
        </span>
        <input type="file" accept=".eml" multiple className="hidden" onChange={(e) => handleFiles(e.target.files)} />
      </label>

      {files.length > 0 && (
        <ul className="mt-4 space-y-1 text-sm text-zinc-400">
          {files.map((f) => (
            <li key={f.name}>{f.name}</li>
          ))}
        </ul>
      )}

      <button
        type="button"
        disabled={files.length === 0 || mutation.isPending}
        onClick={() => mutation.mutate(files)}
        className="mt-4 rounded-md bg-cyan-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-cyan-500 disabled:opacity-40"
      >
        {mutation.isPending ? "Analyzing…" : `Analyze ${files.length || ""} file(s)`}
      </button>

      {results.length > 0 && (
        <ul className="mt-6 space-y-1 text-sm">
          {results.map((r) => (
            <li key={r.name} className={r.status === "ok" ? "text-emerald-400" : "text-red-400"}>
              {r.name}: {r.message}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
