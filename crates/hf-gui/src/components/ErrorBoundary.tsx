import { Component, type ErrorInfo, type ReactNode } from "react";

interface Props {
  children: ReactNode;
  /** Bump this (e.g. the active view id) to auto-recover when the user navigates. */
  resetKey?: string;
}

interface State {
  error: Error | null;
}

// Catches render/lifecycle errors in a subtree so one broken view can't
// white-screen the whole app. Offers a recovery action, and auto-resets when
// `resetKey` changes (e.g. switching views).
export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // Surface for debugging; the console is captured by the dev tooling.
    console.error("[hobot_fuzz] view error:", error, info.componentStack);
  }

  componentDidUpdate(prev: Props) {
    if (prev.resetKey !== this.props.resetKey && this.state.error) {
      this.setState({ error: null });
    }
  }

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;
    return (
      <div className="flex-1 flex items-center justify-center" style={{ padding: "var(--space-xl)" }}>
        <div
          className="surface-card flex flex-col items-center gap-3 text-center"
          style={{ padding: "var(--space-xl)", maxWidth: 480 }}
        >
          <span className="text-sm font-semibold">Something went wrong in this view</span>
          <p className="text-xs text-text-muted" style={{ overflowWrap: "anywhere" }}>
            {error.message || String(error)}
          </p>
          <button
            onClick={() => this.setState({ error: null })}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md"
            style={{ background: "var(--accent)", color: "var(--accent-contrast)", border: "none", cursor: "pointer" }}
          >
            Reload view
          </button>
        </div>
      </div>
    );
  }
}
