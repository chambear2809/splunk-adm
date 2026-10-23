import type { RunResult, SearchClient, SearchRequest } from "./searchClient";
import type { DnsSource } from "./evidence";

interface Pending {
  key: string;
  source: DnsSource;
  controller: AbortController;
  consumers: Set<AbortSignal>;
  promise: Promise<RunResult>;
  start(): void;
}
/** Browser-local admission control; server/role quotas remain authoritative. */
export class OptionalJobBudget {
  private leases = new Map<DnsSource, Pending>();
  private queue: Pending[] = [];
  private inflight = new Map<string, Pending>();
  private core = 0;
  private unverified = 0;
  private listeners = new Set<() => void>();
  get cleanupPending() {
    return this.leases.size;
  }
  /** Leases dropped locally because server-side cleanup could not be confirmed. */
  get cleanupUnverified() {
    return this.unverified;
  }
  subscribe(listener: () => void) {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }
  private notify() {
    this.listeners.forEach((fn) => fn());
  }
  coreStarted() {
    this.core++;
  }
  coreFinished() {
    this.core = Math.max(0, this.core - 1);
    this.drain();
  }
  private drain() {
    if (this.core) return;
    for (const task of [...this.queue]) {
      if (this.leases.size >= 2) return;
      if (this.leases.has(task.source)) continue;
      this.queue.splice(this.queue.indexOf(task), 1);
      task.start();
    }
  }
  run(
    source: DnsSource,
    key: string,
    client: SearchClient,
    request: SearchRequest,
  ): Promise<RunResult> {
    if (request.signal.aborted)
      return Promise.reject(new Error("Investigation cancelled."));
    let task = this.inflight.get(key);
    if (!task) {
      let resolve!: (result: RunResult) => void,
        reject!: (error: unknown) => void;
      const promise = new Promise<RunResult>((yes, no) => {
        resolve = yes;
        reject = no;
      });
      const controller = new AbortController();
      task = {
        key,
        source,
        controller,
        consumers: new Set(),
        promise,
        start: () => {},
      };
      const current = task;
      task.start = () => {
        if (controller.signal.aborted) {
          reject(new Error("Investigation cancelled."));
          return;
        }
        this.leases.set(source, current);
        this.notify();
        let creating = false;
        const release = () => {
          if (this.leases.get(source) !== current) return;
          this.leases.delete(source);
          this.notify();
          this.drain();
        };
        Promise.resolve()
          .then(() =>
            client.search({
              ...request,
              optionalSource: source,
              signal: controller.signal,
              budget: { serverSeconds: 30, clientMilliseconds: 35000 },
              onLifecycle: (event) => {
                if (event.state === "creating") creating = true;
                if (
                  event.state === "released" ||
                  event.state === "cleanup_unverified"
                ) {
                  if (event.state === "cleanup_unverified") {
                    if (this.leases.get(source) === current) this.unverified++;
                  }
                  release();
                }
                request.onLifecycle?.(event);
              },
            }),
          )
          .then(
            (result) => {
              release();
              resolve(result);
            },
            (error) => {
              // Once creation may have reached the server, only native acknowledgement
              // can release this slot. Time passing is not proof of server expiry.
              if (!creating) release();
              reject(error);
            },
          );
      };
      this.inflight.set(key, task);
      this.queue.push(task);
      promise
        .finally(() => {
          if (this.inflight.get(key) === current) this.inflight.delete(key);
        })
        .catch(() => {});
    }
    const current = task;
    current.consumers.add(request.signal);
    return new Promise((resolve, reject) => {
      const abort = () => {
        current.consumers.delete(request.signal);
        if (!current.consumers.size) {
          current.controller.abort();
          const index = this.queue.indexOf(current);
          if (index >= 0) {
            this.queue.splice(index, 1);
            current.start();
          }
        }
        reject(
          new Error(
            "Investigation cancelled; native cleanup may still be pending.",
          ),
        );
      };
      request.signal.addEventListener("abort", abort, { once: true });
      current.promise
        .then(resolve, reject)
        .finally(() => {
          request.signal.removeEventListener("abort", abort);
          current.consumers.delete(request.signal);
        })
        .catch(() => {});
      this.drain();
    });
  }
}
export const optionalJobs = new OptionalJobBudget();
