import { describe, expect, it, vi } from "vitest";
import { OptionalJobBudget } from "./optionalJobs";
import type { SearchClient, SearchRequest } from "./searchClient";

const result = { rows: [], warnings: [], errors: [] };
const request = (signal = new AbortController().signal): SearchRequest => ({
  search: "safe",
  earliest: "1",
  latest: "2",
  maxRows: 65,
  signal,
});
const tick = async () => {
  await Promise.resolve();
  await Promise.resolve();
  await Promise.resolve();
};
describe("optional DNS native execution admission", () => {
  it("keeps a cancelled lease until native acknowledgement and queues superseding work", async () => {
    const budget = new OptionalJobBudget(),
      control = new AbortController();
    const dispatched: SearchRequest[] = [];
    const client: SearchClient = {
      search: vi.fn((req) => {
        dispatched.push(req);
        req.onLifecycle?.({ state: "creating" });
        return new Promise<typeof result>((_resolve, reject) =>
          req.signal.addEventListener("abort", () =>
            reject(Error("cancelled")),
          ),
        );
      }),
    };
    const first = budget
      .run("dns_stream", "one", client, request(control.signal))
      .catch(() => {});
    await tick();
    control.abort();
    await first;
    await tick();
    const secondController = new AbortController();
    const second = budget
      .run("dns_stream", "two", client, request(secondController.signal))
      .catch(() => {});
    await tick();
    expect(dispatched).toHaveLength(1);
    expect(budget.cleanupPending).toBe(1);
    dispatched[0].onLifecycle?.({ state: "released", sid: "native-1" });
    await tick();
    expect(dispatched).toHaveLength(2);
    // A duplicate late callback from the old lease must not free its replacement.
    dispatched[0].onLifecycle?.({ state: "released" });
    expect(budget.cleanupPending).toBe(1);
    secondController.abort();
    await second;
    dispatched[1].onLifecycle?.({ state: "released" });
  });
  it("frees the lease and counts it when cleanup could not be verified", async () => {
    const budget = new OptionalJobBudget(),
      control = new AbortController();
    const dispatched: SearchRequest[] = [];
    const client: SearchClient = {
      search: vi.fn((req) => {
        dispatched.push(req);
        req.onLifecycle?.({ state: "creating" });
        return new Promise<typeof result>((_resolve, reject) =>
          req.signal.addEventListener("abort", () =>
            reject(Error("cancelled")),
          ),
        );
      }),
    };
    const first = budget
      .run("dns_stream", "one", client, request(control.signal))
      .catch(() => {});
    await tick();
    control.abort();
    await first;
    const second = budget.run("dns_stream", "two", client, request());
    void second.catch(() => {});
    await tick();
    expect(dispatched).toHaveLength(1);
    expect(budget.cleanupPending).toBe(1);
    dispatched[0].onLifecycle?.({ state: "cleanup_unverified" });
    await tick();
    expect(budget.cleanupUnverified).toBe(1);
    expect(dispatched).toHaveLength(2);
    expect(budget.cleanupPending).toBe(1);
    // A repeated report from the old lease must not count or free the replacement.
    dispatched[0].onLifecycle?.({ state: "cleanup_unverified" });
    expect(budget.cleanupUnverified).toBe(1);
    expect(budget.cleanupPending).toBe(1);
  });
  it("coalesces identical inflight consumers and prioritizes core searches", async () => {
    const budget = new OptionalJobBudget();
    let resolve!: (value: typeof result) => void;
    const client: SearchClient = {
      search: vi.fn(
        () =>
          new Promise<typeof result>((yes) => {
            resolve = yes;
          }),
      ),
    };
    budget.coreStarted();
    const first = budget.run("dns_hubble", "same", client, request());
    const second = budget.run("dns_hubble", "same", client, request());
    await tick();
    expect(client.search).not.toHaveBeenCalled();
    budget.coreFinished();
    await tick();
    expect(client.search).toHaveBeenCalledTimes(1);
    resolve(result);
    await Promise.all([first, second]);
    expect(budget.cleanupPending).toBe(0);
  });
  it("allows two adapters but never more than one job per adapter", async () => {
    const budget = new OptionalJobBudget();
    const requests: SearchRequest[] = [];
    const client: SearchClient = {
      search: (req) => {
        requests.push(req);
        return new Promise(() => {});
      },
    };
    void budget.run("dns_stream", "s1", client, request());
    void budget.run("dns_stream", "s2", client, request());
    void budget.run("dns_hubble", "h1", client, request());
    await tick();
    expect(requests).toHaveLength(2);
    expect(budget.cleanupPending).toBe(2);
  });
});
