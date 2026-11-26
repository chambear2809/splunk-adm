import { useEffect, useMemo, useState } from "react";
import { pageURL, stateParams, type UrlState } from "./app/urlState";
import { savedViewsFor } from "./app/savedViews";
import type { ServerSavedView } from "./data/collaborationClient";

export function SavedViews({
  state,
  user,
  inSplunk = false,
}: {
  state?: UrlState;
  user?: string;
  inSplunk?: boolean;
}) {
  const store = useMemo(() => savedViewsFor(user), [user]);
  const [views, setViews] = useState(store.read);
  const [shared, setShared] = useState<ServerSavedView[]>([]);
  const [name, setName] = useState("");
  const [visibility, setVisibility] = useState<"private" | "shared">("private");
  const [message, setMessage] = useState("");
  const [copied, setCopied] = useState(false);
  const [copying, setCopying] = useState(false);
  useEffect(() => {
    setViews(store.read());
    setCopied(false);
    setMessage("");
  }, [store]);
  useEffect(() => {
    if (!inSplunk) return;
    const request = new AbortController();
    void import("./data/collaborationClient")
      .then(({ collaborationClient }) =>
        collaborationClient.loadViews(request.signal).then((document) => {
          if (!request.signal.aborted) setShared(document.views);
        }),
      )
      .catch((error) => {
        if (!request.signal.aborted)
          setMessage(
            error instanceof Error
              ? error.message
              : "Shared views are unavailable.",
          );
      });
    return () => request.abort();
  }, [inSplunk]);
  const hrefFor = (viewState: UrlState) => {
    const params = stateParams(viewState);
    if (typeof location === "undefined") return pageURL("map", params);
    const pathname = /\/app\/splunk_adm\//.test(location.pathname)
      ? pageURL("map", params)
      : `${location.pathname}?${params.toString()}`;
    return new URL(pathname, location.origin).toString();
  };
  const copy = async () => {
    if (!state) return;
    setCopying(true);
    try {
      const href = hrefFor(state);
      await navigator.clipboard.writeText(href);
      setCopied(true);
      setMessage("");
    } catch (error) {
      setCopied(false);
      setMessage(
        error instanceof Error && error.message.includes("state")
          ? error.message
          : "Could not copy the validated link.",
      );
    } finally {
      setCopying(false);
    }
  };
  return (
    <section className="atlas-saved-views" aria-labelledby="saved-views-title">
      <h2 id="saved-views-title">Saved views</h2>
      <p>
        Browser saves stay on this workstation. Shared views use the insert-only
        collaboration ledger and restore filters and focus.
      </p>
      <button
        className="secondary-button"
        type="button"
        onClick={copy}
        disabled={!state || copying}
      >
        Copy link
      </button>
      {!state && <p>Build a map before copying its link or saving its view.</p>}
      {copied && <p role="status">Link copied.</p>}
      {!store.enabled && (
        <p role="status">Sign in to save views to this browser.</p>
      )}
      <form
        onSubmit={(event) => {
          event.preventDefault();
          if (!state) return;
          try {
            const saved = store.save(name, state);
            setViews(store.read());
            setName("");
            setMessage("View saved.");
            if (inSplunk && visibility === "shared" && user) {
              const requestId = `view${Date.now().toString(36)}${Math.random()
                .toString(36)
                .slice(2, 10)}`.replace(/[^A-Za-z0-9_-]/g, "");
              void import("./data/collaborationClient")
                .then(({ collaborationClient }) =>
                  collaborationClient.loadViews().then((document) =>
                    collaborationClient.saveViews(
                      [
                        {
                          id:
                            saved.id
                              .replace(/[^A-Za-z0-9_-]/g, "")
                              .slice(0, 80) || requestId,
                          name: saved.name,
                          visibility: "shared" as const,
                          owner: user,
                          state: saved.state,
                        },
                        ...document.views.filter(
                          (view) => view.name !== saved.name,
                        ),
                      ].slice(0, 50),
                      document.revision,
                      requestId,
                    ),
                  ),
                )
                .then((document) => setShared(document.views))
                .catch((error) =>
                  setMessage(
                    error instanceof Error
                      ? error.message
                      : "Shared view could not be stored.",
                  ),
                );
            }
          } catch (error) {
            setMessage(
              error instanceof Error
                ? error.message
                : "View could not be saved.",
            );
          }
        }}
      >
        <label>
          View name{" "}
          <input
            value={name}
            onChange={(event) => setName(event.target.value)}
            disabled={!state || !store.enabled}
          />
        </label>
        {inSplunk && (
          <label>
            Visibility{" "}
            <select
              value={visibility}
              onChange={(event) =>
                setVisibility(event.target.value as "private" | "shared")
              }
            >
              <option value="private">Private</option>
              <option value="shared">Shared with this search head</option>
            </select>
          </label>
        )}
        <button type="submit" disabled={!state || !store.enabled}>
          Save view
        </button>
      </form>
      {message && <p role="alert">{message}</p>}
      <ul>
        {shared.map((view) => (
          <li key={`shared-${view.id}`}>
            <a href={hrefFor(view.state)}>{view.name}</a>{" "}
            <span className="muted">shared · {view.owner}</span>
          </li>
        ))}
        {views.map((view) => (
          <li key={view.id}>
            <a href={hrefFor(view.state)}>{view.name}</a>{" "}
            <button
              type="button"
              onClick={() => {
                try {
                  store.remove(view.id);
                  setViews(store.read());
                } catch (error) {
                  setMessage(
                    error instanceof Error
                      ? error.message
                      : "Saved view could not be deleted.",
                  );
                }
              }}
            >
              Delete
            </button>
          </li>
        ))}
      </ul>
    </section>
  );
}
