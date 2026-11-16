import type { ReactNode } from "react";
import { pageURL } from "../app/urlState";

const TABS = [
  ["setup", "Setup"],
  ["data_health", "Data health"],
] as const;

/** Admin groups configuration and pipeline health behind one nav entry. */
export function AdminPage({
  tab,
  children,
}: {
  tab: (typeof TABS)[number][0];
  children: ReactNode;
}) {
  const search = typeof location === "undefined" ? "" : location.search;
  return (
    <main className="atlas-page atlas-admin">
      <h1 className="atlas-visually-hidden">Admin</h1>
      <nav className="atlas-tabs" aria-label="Admin">
        {TABS.map(([id, label]) => (
          <a
            key={id}
            href={pageURL(id, new URLSearchParams(search))}
            aria-current={tab === id ? "page" : undefined}
          >
            {label}
          </a>
        ))}
      </nav>
      {children}
    </main>
  );
}
