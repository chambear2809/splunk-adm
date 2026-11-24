export const formatTime = (seconds: number, timezone?: string) => {
  try {
    return new Intl.DateTimeFormat(undefined, {
      dateStyle: "medium",
      timeStyle: "medium",
      timeZone: timezone,
    }).format(new Date(seconds * 1000));
  } catch {
    return new Date(seconds * 1000).toISOString();
  }
};
