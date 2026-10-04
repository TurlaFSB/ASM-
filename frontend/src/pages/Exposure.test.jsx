import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../api", () => ({
  getTargets: vi.fn(),
  getExposureSources: vi.fn(),
  setExposureSources: vi.fn(),
  runExposureNow: vi.fn(),
  getExposureFindings: vi.fn(),
  setExposureFindingStatus: vi.fn(),
  getExposureRuns: vi.fn(),
}));
vi.mock("../components/useRole", () => ({ default: () => "admin" }));

import * as api from "../api";
import ToastProvider from "../components/Toast";
import Exposure from "./Exposure";

const src = (name, extra = {}) => ({
  name, label: name.toUpperCase(), description: "d", enabled: false, configured: true, applicable: true, ...extra,
});

function setup(sources) {
  api.getTargets.mockResolvedValue({ data: [{ id: 1, domain: "example.com" }] });
  api.getExposureSources.mockResolvedValue({ data: sources });
  api.getExposureRuns.mockResolvedValue({ data: [] });
  api.getExposureFindings.mockResolvedValue({ data: [] });
  return render(<ToastProvider><Exposure /></ToastProvider>);
}

beforeEach(() => vi.clearAllMocks());

describe("Exposure page", () => {
  it("saves only the enabled sources when a switch is turned on", async () => {
    api.setExposureSources.mockResolvedValue({});
    setup([src("github"), src("xposed", { enabled: true })]);
    const sw = await screen.findByRole("checkbox", { name: "Check GITHUB" });
    await userEvent.click(sw);
    await waitFor(() => expect(api.setExposureSources).toHaveBeenCalledWith(1, ["github", "xposed"]));
    expect(sw).toBeChecked();
  });

  it("puts the switch back and says why when saving fails", async () => {
    api.setExposureSources.mockRejectedValue({ response: { data: { detail: "Nope, not allowed" } } });
    setup([src("github")]);
    const sw = await screen.findByRole("checkbox", { name: "Check GITHUB" });
    await userEvent.click(sw);
    await waitFor(() => expect(sw).not.toBeChecked());
    expect(await screen.findByRole("status")).toHaveTextContent("Nope, not allowed");
  });

  it("explains when no source applies to an IP target and blocks turning one on", async () => {
    setup([src("github", { applicable: false }), src("xposed", { applicable: false })]);
    expect(await screen.findByRole("note")).toHaveTextContent("IP address or an internal host");
    expect(screen.getByRole("checkbox", { name: "Check GITHUB" })).toBeDisabled();
  });

  it("does not show a success toast when a switch is saved", async () => {
    api.setExposureSources.mockResolvedValue({});
    setup([src("github")]);
    await userEvent.click(await screen.findByRole("checkbox", { name: "Check GITHUB" }));
    await waitFor(() => expect(api.setExposureSources).toHaveBeenCalled());
    expect(screen.getByRole("status")).toBeEmptyDOMElement();
  });
});
