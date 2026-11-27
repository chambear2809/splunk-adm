import { useState, type MouseEvent } from "react";
import { copyToClipboard } from "../format";

export function CopyableIp({
  value,
  label,
}: {
  value: string;
  label?: string;
}) {
  const [copied, setCopied] = useState(false);
  const handleCopy = async (event: MouseEvent<HTMLButtonElement>) => {
    event.stopPropagation();
    const ok = await copyToClipboard(value);
    if (ok) {
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    }
  };
  return (
    <button
      type="button"
      className="pl-copy-ip pl-mono"
      title={`Copy ${value}`}
      aria-label={label ? `Copy ${label} ${value}` : `Copy ${value}`}
      onClick={(e) => void handleCopy(e)}
    >
      <span>{value}</span>
      {copied ? (
        <span className="pl-copied-tag" aria-live="polite">
          {" "}
          Copied
        </span>
      ) : null}
    </button>
  );
}
