interface Props {
  path: string | null;
  disabled: boolean;
  error: string | null;
  onPick: () => void;
}

export function ProjectPicker({ path, disabled, error, onPick }: Props) {
  return (
    <section className="card" aria-labelledby="picker-title">
      <h2 id="picker-title">1. Repository</h2>
      <div className="picker-row">
        <button type="button" className="btn" onClick={onPick} disabled={disabled}>
          Select folder…
        </button>
        <div className="path-box" aria-live="polite">
          {path ? (
            <code title={path}>{path}</code>
          ) : (
            <span className="muted">No folder selected</span>
          )}
        </div>
      </div>
      {error ? (
        <p className="inline-error" role="alert">
          {error}
        </p>
      ) : null}
    </section>
  );
}
