import { createRoot } from "react-dom/client";
import { App } from "./App";
import type { SearchConstructor } from "./provider";
import "./styles.css";
interface MVC {
  Components?: {
    getInstance?: (id: string) => unknown;
    revokeInstance?: (id: string) => void;
  };
}
declare global {
  interface Window {
    require?: (
      deps: string[],
      callback: (SearchManager: SearchConstructor, mvc: MVC) => void,
      error?: (error: Error) => void,
    ) => void;
  }
}
function mount(SearchManager?: SearchConstructor, mvc?: MVC) {
  const root = document.getElementById("adm-root");
  if (!root || root.dataset.mounted) return;
  root.dataset.mounted = "true";
  const releaseManager = (id: string) => {
    if (mvc?.Components?.getInstance?.(id)) mvc.Components.revokeInstance?.(id);
  };
  createRoot(root).render(
    <App SearchManager={SearchManager} releaseManager={releaseManager} />,
  );
}
if (__ADM_SPLUNK_BUILD__) {
  const failed = () => {
    const root = document.getElementById("adm-root");
    if (root)
      root.textContent =
        "Unable to load Splunk search integration. Check dashboard JavaScript permissions and reload.";
  };
  if (window.require)
    window.require(
      [
        "splunkjs/mvc/searchmanager",
        "splunkjs/mvc",
        "splunkjs/mvc/simplexml/ready!",
      ],
      mount,
      failed,
    );
  else failed();
} else mount();
