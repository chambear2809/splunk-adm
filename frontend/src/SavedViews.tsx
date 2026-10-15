import { useEffect, useMemo, useState } from "react";
import { pageURL, stateParams, type UrlState } from "./app/urlState";
import { savedViewsFor } from "./app/savedViews";

export function SavedViews({
  state,
  user,
}: {
  state: UrlState;
  user?: string;
}) {
  const store = useMemo(() => savedViewsFor(user), [user]);
  const [views, setViews] = useState(store.read);
  const [name, setName] = useState("");
  const [message, setMessage] = useState("");
  const [copied, setCopied] = useState(false);
  const [copying, setCopying] = useState(false);
  useEffect(() => {
    setViews(store.read());
    setCopied(false);
    setMessage("");
  }, [store]);
  const hrefFor = (viewState: UrlState) => {
    const params = stateParams(viewState);
    if (typeof location === "undefined") return pageURL("map", params);
    const pathname = /\/app\/splunk_adm\//.test(location.pathname)
      ? pageURL("map", params)
      : `${location.pathname}?${params.toString()}`;
    return new URL(pathname, location.origin).toString();
  };
  const copy = async () => {
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
        Saved only for your user in this browser. Links restore scope, time, tab
        and highlight; local filters and focus are not included.
      </p>
      <button
        className="secondary-button"
        type="button"
        onClick={copy}
        disabled={copying}
      >
        Copy link
      </button>
      {copied && <p role="status">Link copied.</p>}
      {!store.enabled && (
        <p role="status">Sign in to save views to this browser.</p>
      )}
      <form
        onSubmit={(event) => {
          event.preventDefault();
          try {
            store.save(name, state);
            setViews(store.read());
            setName("");
            setMessage("View saved.");
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
            disabled={!store.enabled}
          />
        </label>
        <button type="submit" disabled={!store.enabled}>
          Save view
        </button>
      </form>
      {message && <p role="alert">{message}</p>}
      <ul>
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
