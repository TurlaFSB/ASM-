import { Component } from "react";

// One broken page must not blank the whole app: show a way back instead of a white screen.
export default class ErrorBoundary extends Component {
  state = { failed: false };

  static getDerivedStateFromError() { return { failed: true }; }

  componentDidCatch(error, info) { console.error("UI error:", error, info?.componentStack); }

  render() {
    if (!this.state.failed) return this.props.children;
    return (
      <div className="page">
        <div className="empty-state-page">
          <h1>Something went wrong</h1>
          <p>This page hit an unexpected error. Your data is safe. Reload to try again.</p>
          <button type="button" className="btn btn-primary" onClick={() => window.location.reload()}>Reload</button>
        </div>
      </div>
    );
  }
}
