import { getDefaultFetchInit } from "@splunk/splunk-utils/fetch";
import { createRESTURL } from "@splunk/splunk-utils/url";
import { parseUrlState, stateParams, type UrlState } from "../app/urlState";

const object = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === "object" && !Array.isArray(value);

export type ViewVisibility = "private" | "shared";
export interface ServerSavedView {
  id: string;
  name: string;
  visibility: ViewVisibility;
  owner: string;
  team?: string;
  state: UrlState;
}

export interface ViewsDocument {
  revision: string | null;
  views: ServerSavedView[];
}

function unwrap(payload: unknown): Record<string, unknown> {
  if (
    object(payload) &&
    Array.isArray(payload.entry) &&
    payload.entry.length === 1 &&
    object(payload.entry[0]) &&
    object(payload.entry[0].content)
  )
    return payload.entry[0].content;
  if (object(payload)) return payload;
  throw new Error("Collaboration records are incomplete.");
}

function viewState(value: unknown): UrlState | undefined {
  if (!object(value)) return undefined;
  try {
    const params = new URLSearchParams();
    for (const [key, item] of Object.entries(value)) {
      if (typeof item === "string") params.set(key, item);
    }
    return parseUrlState(params, false);
  } catch {
    return undefined;
  }
}

function encodeState(state: UrlState): Record<string, string> {
  return Object.fromEntries(stateParams(state));
}

function viewsOf(payload: unknown): ServerSavedView[] {
  if (!object(payload) || !Array.isArray(payload.views)) return [];
  return payload.views.flatMap((row) => {
    if (!object(row)) return [];
    const state = viewState(row.state);
    if (
      typeof row.id !== "string" ||
      typeof row.name !== "string" ||
      (row.visibility !== "private" && row.visibility !== "shared") ||
      typeof row.owner !== "string" ||
      !state
    )
      return [];
    return [
      {
        id: row.id,
        name: row.name,
        visibility: row.visibility,
        owner: row.owner,
        ...(typeof row.team === "string" ? { team: row.team } : {}),
        state,
      },
    ];
  });
}

export class CollaborationClient {
  constructor(
    private readonly fetcher: typeof fetch = (...args) => fetch(...args),
  ) {}

  private async request(
    kind: "views" | "ownership",
    body?: unknown,
    signal?: AbortSignal,
  ): Promise<Record<string, unknown>> {
    const defaults = getDefaultFetchInit();
    const headers = new Headers(defaults.headers);
    if (body !== undefined) headers.set("Content-Type", "application/json");
    const response = await this.fetcher(
      createRESTURL(`adm/collaboration?kind=${kind}&output_mode=json`, {
        app: "splunk_adm",
        owner: "nobody",
      }),
      {
        ...defaults,
        headers,
        signal,
        method: body === undefined ? "GET" : "POST",
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      },
    );
    const payload: unknown = await response.json().catch(() => undefined);
    if (!response.ok)
      throw new Error(
        object(payload) && typeof payload.error === "string"
          ? payload.error
          : `Collaboration request failed (HTTP ${response.status}).`,
      );
    return unwrap(payload);
  }

  async loadViews(signal?: AbortSignal): Promise<ViewsDocument> {
    const content = await this.request("views", undefined, signal);
    return {
      revision: typeof content.revision === "string" ? content.revision : null,
      views: viewsOf(content.payload),
    };
  }

  async saveViews(
    views: ServerSavedView[],
    expectedRevision: string | null,
    requestId: string,
    signal?: AbortSignal,
  ): Promise<ViewsDocument> {
    const content = await this.request(
      "views",
      {
        expectedRevision,
        requestId,
        payload: {
          views: views.map((view) => ({
            id: view.id,
            name: view.name,
            visibility: view.visibility,
            owner: view.owner,
            ...(view.team ? { team: view.team } : {}),
            state: encodeState(view.state),
          })),
        },
      },
      signal,
    );
    return {
      revision:
        typeof content.committedRevision === "string"
          ? content.committedRevision
          : typeof content.revision === "string"
            ? content.revision
            : expectedRevision,
      views: viewsOf(content.payload),
    };
  }
}

export const collaborationClient = new CollaborationClient();
