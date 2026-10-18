import { expect, test } from "@playwright/test";
import { capturedAction, committedFrames } from "./readiness";

test("precondition rejects an already-selected old DOM before capture", () => {
  expect(() =>
    capturedAction({
      name: "selectCard",
      precondition: () => false,
      settle: async () => 1,
      now: () => 0,
    }),
  ).toThrow("Action precondition failed: selectCard");
});

test("old stable DOM cannot settle before the expected update commits", async () => {
  let frame = 0;
  const end = await committedFrames({
    signal: new AbortController().signal,
    now: () => frame,
    nextFrame: async () => {
      frame++;
    },
    read: () => ({ valid: true, signature: frame <= 8 ? "old" : "selected" }),
    committed: () => frame > 8,
  });
  expect(end).toBe(12);
});

test("lost postcondition, invalid geometry and changed signatures reset frames", async () => {
  let frame = 0;
  const end = await committedFrames({
    signal: new AbortController().signal,
    now: () => frame,
    nextFrame: async () => {
      frame++;
    },
    committed: () => frame !== 4,
    read: () => ({
      valid: frame !== 8,
      signature: frame < 12 ? "first" : "final",
    }),
  });
  expect(end).toBe(15);
});

test("readiness starts at capture and can finish before trigger completion", async () => {
  let now = 100;
  let called = 0;
  const action = capturedAction({
    name: "selectCard",
    precondition: () => true,
    now: () => now,
    settle: async () => {
      called++;
      return 150;
    },
  });
  action.capture();
  expect(called).toBe(1);
  now = 500;
  action.triggerCompleted();
  const timing = await action.result();
  expect(timing.duration).toBe(50);
  expect(timing.eventToTriggerCompletionObservedMs).toBe(400);
  expect(timing.readyBeforeTriggerCompletionObserved).toBe(true);
});

test("a missing capture event fails instead of settling old DOM", async () => {
  const action = capturedAction({
    name: "missing-event",
    precondition: () => true,
    now: () => 0,
    timeoutMs: 10,
    settle: async () => {
      throw new Error("must not run");
    },
  });
  action.triggerCompleted();
  await expect(action.result()).rejects.toThrow("missing event");
});

test("a missing committed postcondition times out despite stable valid geometry", async () => {
  const action = capturedAction({
    name: "missing-selection",
    precondition: () => true,
    now: () => performance.now(),
    timeoutMs: 20,
    settle: (signal) =>
      committedFrames({
        signal,
        now: () => performance.now(),
        read: () => ({ valid: true, signature: "unchanged old DOM" }),
        committed: () => false,
        nextFrame: () => new Promise((resolve) => setTimeout(resolve, 1)),
      }),
  });
  action.capture();
  action.triggerCompleted();
  await expect(action.result()).rejects.toThrow(
    "missing committed postcondition",
  );
});

test("failed trigger fails even when browser readiness already completed", async () => {
  const action = capturedAction({
    name: "failed-click",
    precondition: () => true,
    now: () => 1,
    settle: async () => 2,
  });
  action.capture();
  await Promise.resolve();
  action.triggerFailed(new Error("Playwright click failed"));
  await expect(action.result()).rejects.toThrow("Playwright click failed");
});

test("failed trigger aborts pending browser frame work", async () => {
  let signal: AbortSignal | undefined;
  const action = capturedAction({
    name: "failed-pending-click",
    precondition: () => true,
    now: () => 1,
    settle: (capturedSignal) => {
      signal = capturedSignal;
      return new Promise((_resolve, reject) => {
        signal!.addEventListener("abort", () => reject(signal!.reason));
      });
    },
  });
  action.capture();
  action.triggerFailed(new Error("trigger rejected"));
  await expect(action.result()).rejects.toThrow("trigger rejected");
  expect(signal?.aborted).toBe(true);
});
