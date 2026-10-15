import { useState } from "react";
export function DeepLinkNotice({ message }: { message?: string }) {
  const [dismissed, setDismissed] = useState(false);
  if (!message || dismissed) return null;
  return (
    <div className="atlas-page" role="alert">
      {message}{" "}
      <button
        type="button"
        onClick={() => setDismissed(true)}
        aria-label="Dismiss link notice"
      >
        Dismiss
      </button>
    </div>
  );
}
