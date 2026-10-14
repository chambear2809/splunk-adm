// search-job 3.1.0 ships JavaScript only. This declares just the spike's API.
declare module "@splunk/search-job/SearchJob" {
  interface Subscription {
    unsubscribe(): void;
  }
  interface Observable<T> {
    subscribe(observer: {
      next?: (value: T) => void;
      error?: (error: Error) => void;
    }): Subscription;
  }
  export default class SearchJob {
    static setBaseFetchInit(init: RequestInit): void;
    static create(
      params: Record<string, string>,
      options: { app: string; owner: string; cancelOnUnload: boolean },
    ): SearchJob;
    getResults(params: {
      count: number;
      output_mode: string;
    }): Observable<unknown>;
    cancel(): Observable<unknown>;
  }
}
