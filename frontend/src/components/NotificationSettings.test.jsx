import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../api", () => ({
  getNotificationSettings: vi.fn(),
  updateNotificationSettings: vi.fn(),
  testWebhook: vi.fn(),
  testEmail: vi.fn(),
}));
import * as api from "../api";
import NotificationSettings from "./NotificationSettings";

const base = { target_id: 1, alert_min_severity: "medium", webhook_configured: false, webhook_host: null,
  webhook_format: "json", has_secret: false, email_recipients: [], smtp_configured: true };

beforeEach(() => { vi.clearAllMocks(); });

describe("NotificationSettings email", () => {
  it("saves a parsed, de-spaced recipient list", async () => {
    api.getNotificationSettings.mockResolvedValue({ data: base });
    api.updateNotificationSettings.mockResolvedValue({ data: { ...base, email_recipients: ["a@x.io", "b@x.io"] } });
    render(<NotificationSettings target={{ id: 1 }} />);
    const box = await screen.findByLabelText("Email recipients");
    await userEvent.type(box, "a@x.io; b@x.io  ");
    await userEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() => expect(api.updateNotificationSettings).toHaveBeenCalled());
    expect(api.updateNotificationSettings.mock.calls[0][1].email_recipients).toEqual(["a@x.io", "b@x.io"]);
    expect(await screen.findByText("Saved.")).toBeTruthy();
  });

  it("tells the user when the server has no mail setup and hides the test button", async () => {
    api.getNotificationSettings.mockResolvedValue({ data: { ...base, smtp_configured: false, email_recipients: ["a@x.io"] } });
    render(<NotificationSettings target={{ id: 1 }} />);
    expect(await screen.findByText(/Email is not set up on this server/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Send test email" })).toBeNull();
  });

  it("sends a test email and reports the result", async () => {
    api.getNotificationSettings.mockResolvedValue({ data: { ...base, email_recipients: ["a@x.io"] } });
    api.testEmail.mockResolvedValue({ data: { status: "failed", error: "authentication failed" } });
    render(<NotificationSettings target={{ id: 1 }} />);
    await userEvent.click(await screen.findByRole("button", { name: "Send test email" }));
    expect(await screen.findByText("Test email failed: authentication failed.")).toBeTruthy();
  });
});
