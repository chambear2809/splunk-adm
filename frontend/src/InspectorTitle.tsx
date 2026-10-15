import { useState } from "react";
import { Copy } from "lucide-react";

/** Keep the heading compact without losing the complete collected name. */
export function InspectorTitle({ name }: { name: string }) {
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState(false);
  const [pending, setPending] = useState(false);
  return (
    <div className="atlas-inspector-title">
      <h2 title={name}>{name}</h2>
      <details>
        <summary>Full name</summary>
        <p className="atlas-full-name">{name}</p>
        <button
          className="secondary-button"
          aria-label="Copy full name"
          disabled={pending}
          onClick={async () => {
            setPending(true);
            setCopied(false);
            setError(false);
            try {
              await navigator.clipboard.writeText(name);
              setCopied(true);
            } catch {
              setError(true);
            } finally {
              setPending(false);
            }
          }}
        >
          <Copy size={14} aria-hidden />
          Copy name
        </button>
        {copied && <p role="status">Name copied.</p>}
        {error && (
          <p role="alert">
            Could not copy. Select the full name above to copy it manually.
          </p>
        )}
      </details>
    </div>
  );
}
