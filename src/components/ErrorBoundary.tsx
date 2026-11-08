import { Component, type ErrorInfo, type ReactNode } from 'react';

interface Props {
  children: ReactNode;
}

interface State {
  failed: boolean;
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { failed: false };

  static getDerivedStateFromError(): State {
    return { failed: true };
  }

  componentDidCatch(_error: Error, _info: ErrorInfo): void {
    // Intentionally not logged: render errors may be derived from untrusted finding text.
  }

  render(): ReactNode {
    if (this.state.failed) {
      return (
        <div className="fatal" role="alert">
          <h1>Something went wrong</h1>
          <p>The interface hit an unexpected error. Restart shipcheck and try again.</p>
          <button type="button" className="btn btn-primary" onClick={() => window.location.reload()}>
            Reload
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
