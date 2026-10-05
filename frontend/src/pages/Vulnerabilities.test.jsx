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

describe("Posture checks", () => {
  const posture = { kind: "finding", id: 9, verified: true, severity: "info", name: "Public Amazon S3 listing: acme-files",
    template_id: "cloud-storage-public-amazon", host: "acme-files", matched_at: "https://acme-files.s3.amazonaws.com/",
    cvss_score: null, cve_id: null, tags: ["cloud-storage", "posture", "ownership-unverified", "amazon"] };

  it("labels a posture finding with its check and warns that ownership is unconfirmed", async () => {
    api.getVulnRollup.mockResolvedValue({ data: { items: [posture], findings: 1, lines: 1 } });
    api.getVulnSummary.mockResolvedValue({ data: {} });
    api.getHiddenFindings.mockResolvedValue({ data: { hidden: 0 } });
    render(<ToastProvider><Vulnerabilities /></ToastProvider>);
    expect(await screen.findByText("Cloud storage")).toBeInTheDocument();
    expect(screen.getByText("Ownership unconfirmed")).toBeInTheDocument();
  });

  it("asks the server for posture findings only, then narrows to one check", async () => {
    setup();
    await screen.findByText("Exposed admin panel");
    await userEvent.click(screen.getByRole("button", { name: "Posture checks" }));
    await waitFor(() => expect(api.getVulnRollup).toHaveBeenLastCalledWith(expect.objectContaining({ tag: "posture" })));
    expect(api.getVulnSummary).toHaveBeenLastCalledWith(expect.objectContaining({ tag: "posture" }));
    await userEvent.click(await screen.findByRole("button", { name: "Email security" }));
    await waitFor(() => expect(api.getVulnRollup).toHaveBeenLastCalledWith(expect.objectContaining({ tag: "email-security" })));
    await userEvent.click(screen.getByRole("button", { name: "All findings" }));
    await waitFor(() => expect(api.getVulnRollup).toHaveBeenLastCalledWith({ scope: "latest", triage: "active" }));
  });
});
