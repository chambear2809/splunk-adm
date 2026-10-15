// search-job 3.1.0 ships JavaScript only.
declare module "@splunk/search-job/SearchJob" {
  interface Subscription {
    unsubscribe(): void;
  }
  interface Observable<T> {
    subscribe(observer: {
      next?: (value: T) => void;
      error?: (error: Error) => void;
      complete?: () => void;
    }): Subscription;
  }
  export default class SearchJob {
    static setBaseFetchInit(init: RequestInit): void;
    static create(
      params: Record<string, string>,
      options: { app: string; owner: string; cancelOnUnload: boolean },
    ): SearchJob;
    getProgress(): Observable<unknown>;
    getResults(params: {
      count: number;
      output_mode: string;
    }): Observable<unknown>;
    cancel(): Observable<unknown>;
  }
}
