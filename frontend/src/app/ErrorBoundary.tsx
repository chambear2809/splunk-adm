import { Component, type ErrorInfo, type ReactNode } from "react";

/** Keep a failed panel from blanking the rest of Atlas. */
export class ErrorBoundary extends Component<
  { children: ReactNode; label: string },
  { error?: string }
> {
  state: { error?: string } = {};

  static getDerivedStateFromError(error: Error) {
    return { error: error.message || "This view failed to render." };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    void error;
    void info;
  }

  render() {
    if (this.state.error)
      return (
        <section className="callout warn" role="alert">
          <h2>{this.props.label} could not be shown</h2>
          <p>{this.state.error}</p>
          <button
            type="button"
            className="secondary-button"
            onClick={() => this.setState({ error: undefined })}
          >
            Try again
          </button>
        </section>
      );
    return this.props.children;
  }
}
