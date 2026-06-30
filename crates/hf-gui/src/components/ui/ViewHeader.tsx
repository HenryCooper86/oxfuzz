// The standard page header for a view: a title and a one-line description, with
// consistent type scale and spacing. Use at the top of every primary view so
// headers share one vertical rhythm.
export function ViewHeader({ title, description }: { title: string; description?: string }) {
  return (
    <div>
      <h1 className="text-xl font-semibold">{title}</h1>
      {description && <p className="text-sm text-text-secondary mt-0.5">{description}</p>}
    </div>
  );
}
