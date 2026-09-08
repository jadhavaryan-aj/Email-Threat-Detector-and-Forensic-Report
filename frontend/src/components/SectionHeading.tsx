export function SectionHeading({ children, count }: { children: React.ReactNode; count?: number }) {
  return (
    <h2 className="mb-2.5 flex items-center gap-2 text-xs font-semibold tracking-wide text-zinc-400 uppercase">
      {children}
      {count !== undefined && <span className="font-mono text-zinc-600 normal-case">({count})</span>}
    </h2>
  );
}
