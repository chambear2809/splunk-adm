export type PreviewField = "earliest" | "latest";

export type PreviewParser<Result> = (
  raw: string,
  signal: AbortSignal,
) => Promise<Result>;

/** Serialize previews per field and discard results from superseded requests. */
export function createTimePreview<Result>(parse: PreviewParser<Result>) {
  const revisions: Record<PreviewField, number> = { earliest: 0, latest: 0 };
  const controllers: Partial<Record<PreviewField, AbortController>> = {};

  const cancel = (field?: PreviewField) => {
    const fields = field ? [field] : (["earliest", "latest"] as const);
    for (const name of fields) {
      controllers[name]?.abort();
      controllers[name] = undefined;
      revisions[name] += 1;
    }
  };

  const request = async (
    field: PreviewField,
    raw: string,
    apply: (result: Result) => void,
    fail: (error: unknown) => void,
  ) => {
    cancel(field);
    const revision = revisions[field];
    const controller = new AbortController();
    controllers[field] = controller;
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, 10000);
    try {
      const result = await parse(raw, controller.signal);
      if (revisions[field] === revision && !controller.signal.aborted)
        apply(result);
    } catch (error) {
      if (
        revisions[field] === revision &&
        (!controller.signal.aborted || timedOut)
      )
        fail(error);
    } finally {
      clearTimeout(timer);
    }
  };

  return { request, cancel };
}
