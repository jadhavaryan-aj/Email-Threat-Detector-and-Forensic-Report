export function Skeleton({ className = "" }: { className?: string }) {
  return <div className={`animate-pulse rounded bg-zinc-800/80 ${className}`} />;
}

export function StatTileSkeleton() {
  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-4">
      <Skeleton className="h-3 w-20" />
      <Skeleton className="mt-2 h-7 w-12" />
    </div>
  );
}

export function TableRowSkeleton() {
  return (
    <div className="flex items-center justify-between gap-3 rounded-md border border-zinc-800 px-3 py-2.5">
      <div className="min-w-0 flex-1 space-y-1.5">
        <Skeleton className="h-3.5 w-2/3" />
        <Skeleton className="h-3 w-1/3" />
      </div>
      <Skeleton className="h-5 w-16 shrink-0" />
    </div>
  );
}

export function DashboardSkeleton() {
  return (
    <div>
      <Skeleton className="mb-1 h-6 w-56" />
      <Skeleton className="mb-6 h-4 w-80" />
      <div className="mb-8 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
        {Array.from({ length: 5 }).map((_, i) => (
          <StatTileSkeleton key={i} />
        ))}
      </div>
      <div className="space-y-2">
        {Array.from({ length: 3 }).map((_, i) => (
          <TableRowSkeleton key={i} />
        ))}
      </div>
    </div>
  );
}
