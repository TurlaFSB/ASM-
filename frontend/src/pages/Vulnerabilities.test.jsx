import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../api", () => ({
  getVulnRollup: vi.fn(),
  getVulnSummary: vi.fn(),
  setFindingTriage: vi.fn(),
  getHiddenFindings: vi.fn(),
}));
vi.mock("../components/useRole", () => ({ default: () => "admin" }));

import * as api from "../api";
import ToastProvider from "../components/Toast";
import Vulnerabilities from "./Vulnerabilities";

const finding = {
  kind: "finding", id: 7, verified: true, severity: "high", name: "Exposed admin panel", template_id: "admin-panel",
  host: "app.example.com", matched_at: "https://app.example.com/admin", cvss_score: null, cve_id: null,
};

function setup(hidden = 0) {
  api.getVulnRollup.mockResolvedValue({ data: { items: [finding], findings: 1, lines: 1 } });
  api.getVulnSummary.mockResolvedValue({ data: {} });
  api.getHiddenFindings.mockResolvedValue({ data: { hidden } });
  api.setFindingTriage.mockResolvedValue({});
  return render(<ToastProvider><Vulnerabilities /></ToastProvider>);
}

async function openMenu(item) {
  await userEvent.click(await screen.findByRole("button", { name: "Triage Exposed admin panel" }));
  await userEvent.click(await screen.findByRole("menuitem", { name: item }));
}

beforeEach(() => vi.clearAllMocks());

describe("Finding triage", () => {
  it("applies a one-click status straight away", async () => {
    setup();
    await openMenu("In progress");
    await waitFor(() => expect(api.setFindingTriage).toHaveBeenCalledWith({ ids: [7], status: "in_progress" }));
  });

  it("will not save a false positive without a reason", async () => {
    setup();
    await openMenu("False positive...");
    const save = await screen.findByRole("button", { name: "Save decision" });
    expect(save).toBeDisabled();
    await userEvent.type(screen.getByLabelText("Reason"), "ab");
    expect(save).toBeDisabled();
    await userEvent.type(screen.getByLabelText("Reason"), "c");
    expect(save).toBeEnabled();
    await userEvent.click(save);
    await waitFor(() => expect(api.setFindingTriage).toHaveBeenCalledWith({ ids: [7], status: "false_positive", note: "abc" }));
  });

  it("sends a review period when accepting a risk", async () => {
    setup();
    await openMenu("Accept risk...");
    await userEvent.type(await screen.findByLabelText("Reason"), "Behind VPN, fix planned");
    await userEvent.click(screen.getByRole("button", { name: "Save decision" }));
    await waitFor(() => expect(api.setFindingTriage).toHaveBeenCalledWith(
      { ids: [7], status: "accepted_risk", note: "Behind VPN, fix planned", expires_in_days: 90 }));
  });

  it("tells the user how many findings are hidden and offers to show them", async () => {
    setup(2);
    expect(await screen.findByText(/2 findings are hidden/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Show them" }));
    await waitFor(() => expect(api.getVulnRollup).toHaveBeenLastCalledWith(expect.objectContaining({ triage: "triaged" })));
  });
});
