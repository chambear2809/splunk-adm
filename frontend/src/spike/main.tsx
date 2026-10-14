import { createRoot } from "react-dom/client";
import SplunkThemeProvider from "@splunk/themes/SplunkThemeProvider";
import { getThemeOptions } from "@splunk/splunk-utils/themes";
import { SpikePage } from "./SpikePage";
import { spikePage } from "./settings";
import { toolkitDefault } from "./interop";
import { resolveUserTheme } from "./theme";

const ThemeProvider = toolkitDefault(SplunkThemeProvider);
const ROOT_ID = "atlas-root";
const MOUNT_TIMEOUT_MS = 30000;

function mount(node: HTMLElement) {
  if (node.dataset.mounted) return;
  node.dataset.mounted = "true";
  void resolveUserTheme()
    .then((preference) => {
      createRoot(node).render(
        <ThemeProvider {...getThemeOptions(preference)}>
          <SpikePage preference={preference} />
        </ThemeProvider>,
      );
    })
    .catch((error: unknown) => {
      node.textContent = `Toolkit bootstrap failed: ${String(error)}`;
    });
}

// Simple XML may render its <html> panel after script= loads. Waiting on the
// DOM keeps the bundle free of SplunkJS (splunkjs/mvc) readiness modules.
function whenRootExists(found: (node: HTMLElement) => void) {
  const existing = document.getElementById(ROOT_ID);
  if (existing) return found(existing);
  const observer = new MutationObserver(() => {
    const node = document.getElementById(ROOT_ID);
    if (!node) return;
    observer.disconnect();
    clearTimeout(timer);
    found(node);
  });
  const timer = setTimeout(() => {
    observer.disconnect();
    console.error("Application Atlas mount node did not appear.");
  }, MOUNT_TIMEOUT_MS);
  observer.observe(document.documentElement, {
    childList: true,
    subtree: true,
  });
}

try {
  spikePage(location.pathname);
  whenRootExists(mount);
} catch (error) {
  whenRootExists((node) => {
    node.textContent = `Toolkit bootstrap failed: ${String(error)}`;
  });
}
