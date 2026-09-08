import { useQuery } from "@tanstack/react-query";
import { listCases } from "../api/cases";
import { CaseTable } from "../components/CaseTable";
import { TableRowSkeleton } from "../components/Skeleton";

export function CaseListPage() {
  const { data, isLoading, error } = useQuery({ queryKey: ["cases"], queryFn: () => listCases() });

  return (
    <div>
      <h1 className="mb-4 text-xl font-semibold text-zinc-100">Cases</h1>
      {isLoading && (
        <div className="space-y-2">
          <TableRowSkeleton />
          <TableRowSkeleton />
          <TableRowSkeleton />
        </div>
      )}
      {error && <p className="text-sm text-red-400">Failed to load cases.</p>}
      {data && <CaseTable cases={data} />}
    </div>
  );
}
