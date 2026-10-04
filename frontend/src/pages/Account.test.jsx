import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../api", () => ({
  getMe: vi.fn(), getApiTokens: vi.fn(), createApiToken: vi.fn(), revokeApiToken: vi.fn(),
}));

import * as api from "../api";
import ToastProvider from "../components/Toast";
import Account from "./Account";

function setup(role = "admin", tokens = []) {
  api.getMe.mockResolvedValue({ data: { username: "pranav", role } });
  api.getApiTokens.mockResolvedValue({ data: tokens });
  return render(<ToastProvider><Account /></ToastProvider>);
}

beforeEach(() => vi.clearAllMocks());

describe("Account page", () => {
  it("creates a token, shows the secret once and refreshes the list", async () => {
    api.createApiToken.mockResolvedValue({ data: { id: 1, token: "asm_secretvalue123" } });
    setup();
    await userEvent.click(await screen.findByRole("button", { name: /New token/ }));
    const create = screen.getByRole("button", { name: "Create token" });
    expect(create).toBeDisabled();
    await userEvent.type(screen.getByLabelText("Name"), "CI pipeline");
    await userEvent.click(create);
    await waitFor(() => expect(api.createApiToken).toHaveBeenCalledWith({ name: "CI pipeline", scope: "read", expires_in_days: 90 }));
    expect(await screen.findByDisplayValue("asm_secretvalue123")).toBeInTheDocument();
    expect(screen.getByText(/only time the token is shown/)).toBeInTheDocument();
    expect(api.getApiTokens).toHaveBeenCalledTimes(2);
  });

  it("sends no expiry for 'Never' and lets admins pick full access", async () => {
    api.createApiToken.mockResolvedValue({ data: { id: 2, token: "asm_x" } });
    setup();
    await userEvent.click(await screen.findByRole("button", { name: /New token/ }));
    await userEvent.type(screen.getByLabelText("Name"), "deploy");
    await userEvent.click(screen.getByRole("button", { name: "Full access" }));
    await userEvent.click(screen.getByRole("button", { name: "Never" }));
    await userEvent.click(screen.getByRole("button", { name: "Create token" }));
    await waitFor(() => expect(api.createApiToken).toHaveBeenCalledWith({ name: "deploy", scope: "write", expires_in_days: null }));
  });

  it("viewers only get read-only tokens", async () => {
    setup("viewer");
    await userEvent.click(await screen.findByRole("button", { name: /New token/ }));
    expect(screen.queryByRole("button", { name: "Full access" })).not.toBeInTheDocument();
    expect(screen.getByText(/cannot create tokens that change data/)).toBeInTheDocument();
  });

  it("revokes only after confirmation", async () => {
    api.revokeApiToken.mockResolvedValue({});
    setup("admin", [{ id: 7, name: "old", prefix: "asm_abcd1234", scope: "read", created_at: "2026-10-01T00:00:00Z", last_used_at: null, expires_at: null, revoked_at: null }]);
    await userEvent.click(await screen.findByRole("button", { name: "Actions for token old" }));
    await userEvent.click(await screen.findByRole("menuitem", { name: "Revoke" }));
    expect(api.revokeApiToken).not.toHaveBeenCalled();
    await userEvent.click(await screen.findByRole("button", { name: "Revoke" }));
    await waitFor(() => expect(api.revokeApiToken).toHaveBeenCalledWith(7));
  });

  it("shows revoked and expired tokens as inactive without a menu", async () => {
    setup("admin", [
      { id: 1, name: "gone", prefix: "asm_a", scope: "read", revoked_at: "2026-10-02T00:00:00Z", expires_at: null },
      { id: 2, name: "stale", prefix: "asm_b", scope: "write", revoked_at: null, expires_at: "2020-01-01T00:00:00Z" },
    ]);
    expect(await screen.findByText("Revoked")).toBeInTheDocument();
    expect(screen.getByText("Expired")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Actions for token/ })).not.toBeInTheDocument();
  });
});
