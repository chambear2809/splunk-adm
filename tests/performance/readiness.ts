export type FrameState = { valid: boolean; signature: string };

/** Count stable frames only after the intended DOM update has committed. */
export async function committedFrames(options: {
  read: () => FrameState;
  committed: () => boolean;
  nextFrame: (signal: AbortSignal) => Promise<void>;
  signal: AbortSignal;
  now: () => number;
  onFrame?: (
    frame: FrameState & { at: number; committed: boolean; readMs: number },
  ) => void;
}) {
  let previous: string | undefined;
  let same = 0;
  while (!options.signal.aborted) {
    await options.nextFrame(options.signal);
    options.signal.throwIfAborted();
    const at = options.now();
    const frame = options.read();
    const committed = options.committed();
    options.onFrame?.({ ...frame, at, committed, readMs: options.now() - at });
    if (!frame.valid || !committed) {
      previous = undefined;
      same = 0;
      continue;
    }
    same = frame.signature === previous ? same + 1 : 0;
    previous = frame.signature;
    // Three unchanged frame comparisons after the first committed frame.
    if (same >= 3) return options.now();
  }
  options.signal.throwIfAborted();
  throw new Error("Readiness aborted");
}

/** Browser readiness starts at capture, independently of automation completion. */
export function capturedAction(options: {
  name: string;
  precondition: () => boolean;
  settle: (signal: AbortSignal) => Promise<number>;
  now: () => number;
  timeoutMs?: number;
}) {
  if (!options.precondition())
    throw new Error(`Action precondition failed: ${options.name}`);
  const controller = new AbortController();
  let start: number | undefined;
  let triggerObservedAt: number | undefined;
  let resolveReady!: (end: number) => void;
  let rejectReady!: (error: unknown) => void;
  let resolveTrigger!: () => void;
  let rejectTrigger!: (error: unknown) => void;
  const ready = new Promise<number>((resolve, reject) => {
    resolveReady = resolve;
    rejectReady = reject;
  });
  const trigger = new Promise<void>((resolve, reject) => {
    resolveTrigger = resolve;
    rejectTrigger = reject;
  });
  // Node may still be awaiting its trigger when a browser timeout occurs.
  void ready.catch(() => {});
  void trigger.catch(() => {});
  const deadline = setTimeout(() => {
    const error = new Error(
      `Action readiness timed out: ${options.name} (${start === undefined ? "missing event" : "missing committed postcondition or stable frames"})`,
    );
    controller.abort(error);
    rejectReady(error);
  }, options.timeoutMs ?? 15000);
  const clearDeadline = () => clearTimeout(deadline);
  void ready.then(clearDeadline, clearDeadline);
  return {
    capture() {
      if (start !== undefined || controller.signal.aborted) return;
      start = options.now();
      void options.settle(controller.signal).then(resolveReady, rejectReady);
    },
    triggerCompleted() {
      triggerObservedAt = options.now();
      resolveTrigger();
    },
    triggerFailed(error: unknown) {
      controller.abort(error);
      rejectReady(error);
      rejectTrigger(error);
    },
    async result() {
      // A ready DOM never turns a failed automation action into success.
      await trigger;
      const end = await ready;
      if (start === undefined || triggerObservedAt === undefined)
        throw new Error(`Action event/trigger missing: ${options.name}`);
      return {
        start,
        end,
        duration: end - start,
        triggerCompletionObservedAt: triggerObservedAt,
        eventToTriggerCompletionObservedMs: triggerObservedAt - start,
        readyBeforeTriggerCompletionObserved: end < triggerObservedAt,
        committedPostcondition: true,
      };
    },
  };
}
