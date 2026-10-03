import { Link } from "react-router-dom";

export default function NotFound() {
  return (
    <div className="page">
      <div className="empty-state-page">
        <h1>Page not found</h1>
        <p>That address does not exist in this app.</p>
        <Link to="/" className="btn btn-primary">Back to overview</Link>
      </div>
    </div>
  );
}
