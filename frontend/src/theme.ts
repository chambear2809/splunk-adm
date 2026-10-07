import { useEffect, useState } from "react";

export type Theme = "light" | "dark";

declare global {
  interface Window {
    __splunk_page_theme__?: string;
  }
}

interface ThemeEnv {
  win?: Pick<Window, "__splunk_page_theme__" | "matchMedia">;
  doc?: Pick<Document, "documentElement" | "body">;
}

const fromText = (v: string | null | undefined): Theme | undefined =>
  v === "dark" || v === "light" ? v : undefined;

function fromElement(el: Element | null | undefined): Theme | undefined {
  if (!el) return undefined;
  const attr =
    fromText(el.getAttribute("data-theme")) ??
    fromText(el.getAttribute("data-splunk-theme"));
  if (attr) return attr;
  for (const c of Array.from(el.classList ?? []))
    if (/(^|[-_])theme[-_]?dark$|^dark[-_]theme$/i.test(c)) return "dark";
  return undefined;
}

/**
 * Splunk Web publishes the page theme as `window.__splunk_page_theme__`
 * (read by Splunk's own getCurrentTheme helpers). Explicit theme markers on
 * <html>/<body> come next; the OS preference applies only outside Splunk.
 */
export function detectTheme(env: ThemeEnv = {}, inSplunk = false): Theme {
  const win = env.win ?? (typeof window !== "undefined" ? window : undefined);
  const doc =
    env.doc ?? (typeof document !== "undefined" ? document : undefined);
  const splunk = fromText(win?.__splunk_page_theme__);
  if (splunk) return splunk;
  const marked =
    fromElement(doc?.documentElement) ?? fromElement(doc?.body ?? null);
  if (marked) return marked;
  if (inSplunk) return "light";
  return win?.matchMedia?.("(prefers-color-scheme: dark)").matches
    ? "dark"
    : "light";
}

/** Tracks the effective theme; `override` (from the URL or tests) wins. */
export function useTheme(inSplunk: boolean, override?: Theme): Theme {
  const [theme, setTheme] = useState<Theme>(
    () => override ?? detectTheme({}, inSplunk),
  );
  useEffect(() => {
    if (override) {
      setTheme(override);
      return;
    }
    const update = () => setTheme(detectTheme({}, inSplunk));
    const media = window.matchMedia?.("(prefers-color-scheme: dark)");
    media?.addEventListener?.("change", update);
    const observer = new MutationObserver(update);
    for (const el of [document.documentElement, document.body])
      observer.observe(el, {
        attributes: true,
        attributeFilter: ["class", "data-theme", "data-splunk-theme"],
      });
    update();
    return () => {
      media?.removeEventListener?.("change", update);
      observer.disconnect();
    };
  }, [inSplunk, override]);
  return theme;
}
