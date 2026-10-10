import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../api", () => ({
  login: vi.fn(), getSetupStatus: vi.fn(), setupAccount: vi.fn(), mfaVerify: vi.fn(),
}));
vi.mock("../components/useRole", () => ({ resetRole: vi.fn() }));

import * as api from "../api";
import Login from "./Login";

beforeEach(() => {
  vi.clearAllMocks();
  api.getSetupStatus.mockResolvedValue({ data: { needs_setup: false } });
});

async function fillAndSubmit() {
  await userEvent.type(screen.getByLabelText("Username"), "pranav");
  await userEvent.type(screen.getByLabelText("Password"), "correct horse battery");
  await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
}

describe("Login", () => {
  it("signs in with one step when two-step is off", async () => {
    api.login.mockResolvedValue({ data: { access_token: "t" } });
    const onLogin = vi.fn();
    render(<Login onLogin={onLogin} />);
    await fillAndSubmit();
    await waitFor(() => expect(onLogin).toHaveBeenCalled());
    expect(api.mfaVerify).not.toHaveBeenCalled();
  });

  it("asks for a code when two-step is on and only finishes after it verifies", async () => {
    api.login.mockResolvedValue({ data: { mfa_required: true, mfa_token: "challenge" } });
    api.mfaVerify.mockResolvedValue({ data: {} });
    const onLogin = vi.fn();
    render(<Login onLogin={onLogin} />);
    await fillAndSubmit();
    expect(await screen.findByLabelText("Code")).toBeInTheDocument();
    expect(onLogin).not.toHaveBeenCalled();
    await userEvent.type(screen.getByLabelText("Code"), "123456");
    await userEvent.click(screen.getByRole("button", { name: "Verify" }));
    await waitFor(() => expect(api.mfaVerify).toHaveBeenCalledWith("challenge", "123456"));
    await waitFor(() => expect(onLogin).toHaveBeenCalled());
  });

  it("shows a clear error for a wrong code and lets the person start again", async () => {
    api.login.mockResolvedValue({ data: { mfa_required: true, mfa_token: "challenge" } });
    api.mfaVerify.mockRejectedValue({ response: { status: 401 } });
    const onLogin = vi.fn();
    render(<Login onLogin={onLogin} />);
    await fillAndSubmit();
    await userEvent.type(await screen.findByLabelText("Code"), "000000");
    await userEvent.click(screen.getByRole("button", { name: "Verify" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/wrong or the sign-in expired/);
    expect(onLogin).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button", { name: "Start again" }));
    expect(await screen.findByLabelText("Username")).toBeInTheDocument();
  });
});
