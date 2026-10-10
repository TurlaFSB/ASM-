import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../api", () => ({ getAudit: vi.fn() }));

import * as api from "../api";
import Audit from "./Audit";
import { label, summarize } from "../lib/audit";

const row = (id, username, action, extra = {}) => ({ id, username, action, ip_address: "10.0.0.1", created_at: new Date().toISOString(), detail: null, ...extra });
const reply = (rows, total = rows.length) => ({ data: rows, headers: { "x-total-count": String(total) } });

beforeEach(() => vi.clearAllMocks());

describe("Audit log", () => {
  it("lists events with readable names and shows failures prominently", async () => {
    api.getAudit.mockResolvedValue(reply([
      row(2, "bob", "login_failed"),
      row(1, "root", "user_created", { detail: { user: "viewer1", role: "viewer", nested: { x: 1 } } }),
    ]));
    render(<Audit />);
    expect(await screen.findByText("Login failed")).toHaveClass("badge-sev-high");
    expect(screen.getByText("User created")).toHaveClass("badge-sev-info");
    expect(screen.getByText("user: viewer1, role: viewer")).toBeInTheDocument();   // nested objects are not dumped
    expect(screen.getByText("Showing 2 of 2.")).toBeInTheDocument();
  });

  it("narrows by kind of event and by username", async () => {
    api.getAudit.mockResolvedValue(reply([row(1, "bob", "login_failed")]));
    render(<Audit />);
    await screen.findByText("Login failed");
    await userEvent.click(screen.getByRole("button", { name: "Sign-in" }));
    await waitFor(() => expect(api.getAudit).toHaveBeenLastCalledWith(expect.objectContaining({ offset: 0, action: expect.stringContaining("login_failed") })));
    await userEvent.type(screen.getByLabelText("Username"), "bob");
    await waitFor(() => expect(api.getAudit).toHaveBeenLastCalledWith(expect.objectContaining({ username: "bob" })), { timeout: 2000 });
  });

  it("loads the next page from the current offset", async () => {
    api.getAudit.mockResolvedValueOnce(reply([row(2, "a", "logout"), row(1, "a", "login_success")], 3));
    render(<Audit />);
    await screen.findByText("Showing 2 of 3.");
    api.getAudit.mockResolvedValueOnce(reply([row(0, "a", "setup_completed")], 3));
    await userEvent.click(screen.getByRole("button", { name: "Load more" }));
    await screen.findByText("Showing 3 of 3.");
    expect(api.getAudit).toHaveBeenLastCalledWith(expect.objectContaining({ offset: 2 }));
    expect(screen.queryByRole("button", { name: "Load more" })).not.toBeInTheDocument();
  });

  it("explains an empty result and a failure", async () => {
    api.getAudit.mockResolvedValueOnce(reply([]));
    const { unmount } = render(<Audit />);
    expect(await screen.findByText(/No entries match/)).toBeInTheDocument();
    unmount();
    api.getAudit.mockRejectedValueOnce(new Error("x"));
    render(<Audit />);
    expect(await screen.findByText(/Could not load the audit log/)).toBeInTheDocument();
  });

  it("formats labels and details", () => {
    expect(label("mfa_recovery_regenerated")).toBe("Mfa recovery regenerated");
    expect(summarize({ a_b: 1, c: null, d: { e: 1 } })).toBe("a b: 1");
    expect(summarize(null)).toBe("");
  });
});
