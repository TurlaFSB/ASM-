import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../api", () => ({ getTicketing: vi.fn(), updateTicketing: vi.fn(), checkTicketing: vi.fn() }));
import * as api from "../api";
import TicketingSettings from "./TicketingSettings";

const base = { target_id: 1, provider: "github", configured: true, missing: [], destination: null, min_severity: "high", recent: [] };

beforeEach(() => { vi.clearAllMocks(); });

describe("TicketingSettings", () => {
  it("explains what is missing when the server has no provider", async () => {
    api.getTicketing.mockResolvedValue({ data: { ...base, provider: null, configured: false, missing: ["ASM_TICKETS_PROVIDER"] } });
    render(<TicketingSettings target={{ id: 1 }} />);
    expect(await screen.findByText(/Ticketing is not set up on this server/)).toBeTruthy();
    expect(screen.queryByLabelText("Ticket destination")).toBeNull();
  });

  it("names the missing variables when a provider is chosen but incomplete", async () => {
    api.getTicketing.mockResolvedValue({ data: { ...base, provider: "jira", configured: false, missing: ["ASM_JIRA_TOKEN"] } });
    render(<TicketingSettings target={{ id: 1 }} />);
    expect(await screen.findByText(/Jira is chosen on this server but needs ASM_JIRA_TOKEN/)).toBeTruthy();
  });

  it("saves the destination and threshold, then offers a connection check", async () => {
    api.getTicketing.mockResolvedValue({ data: base });
    api.updateTicketing.mockResolvedValue({ data: { ...base, destination: "acme/sec", min_severity: "critical" } });
    api.checkTicketing.mockResolvedValue({ data: { ok: true, message: "Repository acme/sec is reachable and accepts issues" } });
    render(<TicketingSettings target={{ id: 1 }} />);
    await userEvent.type(await screen.findByLabelText("Ticket destination"), " acme/sec ");
    await userEvent.click(screen.getByRole("button", { name: "Critical" }));
    await userEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() => expect(api.updateTicketing).toHaveBeenCalledWith(1, { destination: "acme/sec", min_severity: "critical" }));
    await userEvent.click(await screen.findByRole("button", { name: "Check connection" }));
    expect(await screen.findByText(/is reachable and accepts issues/)).toBeTruthy();
  });

  it("shows the server's reason when saving is refused", async () => {
    api.getTicketing.mockResolvedValue({ data: base });
    api.updateTicketing.mockRejectedValue({ response: { data: { detail: "Use the form owner/repository, for example acme/security-findings" } } });
    render(<TicketingSettings target={{ id: 1 }} />);
    await userEvent.type(await screen.findByLabelText("Ticket destination"), "nope");
    await userEvent.click(screen.getByRole("button", { name: "Save changes" }));
    expect(await screen.findByText(/Use the form owner\/repository/)).toBeTruthy();
  });

  it("lists recent tickets with links, and failures with their reason", async () => {
    api.getTicketing.mockResolvedValue({ data: { ...base, destination: "acme/sec", recent: [
      { id: 1, severity: "high", title: "[ASM] High: x", status: "created", key: "#7", url: "https://github.com/acme/sec/issues/7", error: null },
      { id: 2, severity: "critical", title: "[ASM] Critical: y", status: "failed", key: null, url: null, error: "timeout" },
    ] } });
    render(<TicketingSettings target={{ id: 1 }} />);
    const link = await screen.findByRole("link", { name: /#7/ });
    expect(link.getAttribute("href")).toBe("https://github.com/acme/sec/issues/7");
    expect(link.getAttribute("rel")).toContain("noopener");
    expect(screen.getByText("Not created: timeout")).toBeTruthy();
  });
});
