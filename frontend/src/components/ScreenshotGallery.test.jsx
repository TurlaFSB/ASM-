import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../api", () => ({ getScanScreenshots: vi.fn(), getScanScreenshotImage: vi.fn() }));
import * as api from "../api";
import ScreenshotGallery from "./ScreenshotGallery";

beforeEach(() => {
  vi.clearAllMocks();
  URL.createObjectURL = vi.fn(() => "blob:fake");
  URL.revokeObjectURL = vi.fn();
});

describe("ScreenshotGallery", () => {
  it("lists pictures, loads them and opens one larger", async () => {
    api.getScanScreenshots.mockResolvedValue({ data: { screenshots: [{ id: 0, host: "a.test", url: "https://a.test" }] } });
    api.getScanScreenshotImage.mockResolvedValue({ data: new Blob(["x"]) });
    render(<ScreenshotGallery scanId={7} onClose={() => {}} />);
    const img = await screen.findByAltText("Screenshot of a.test");
    expect(img.getAttribute("src")).toBe("blob:fake");
    expect(api.getScanScreenshotImage).toHaveBeenCalledWith(7, 0);
    await userEvent.click(screen.getByRole("button", { name: "Open screenshot of a.test" }));
    expect(await screen.findByText("https://a.test")).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "Back to all" }));
    expect(screen.queryByText("https://a.test")).toBeNull();
  });

  it("explains when there are none", async () => {
    api.getScanScreenshots.mockResolvedValue({ data: { screenshots: [] } });
    render(<ScreenshotGallery scanId={7} onClose={() => {}} />);
    expect(await screen.findByText(/No screenshots for this scan/)).toBeTruthy();
  });

  it("shows an error when the list cannot be loaded", async () => {
    api.getScanScreenshots.mockRejectedValue(new Error("x"));
    render(<ScreenshotGallery scanId={7} onClose={() => {}} />);
    expect((await screen.findByRole("alert")).textContent).toMatch(/Could not load the screenshots/);
  });

  it("marks a picture that fails to load", async () => {
    api.getScanScreenshots.mockResolvedValue({ data: { screenshots: [{ id: 0, host: "a.test", url: null }] } });
    api.getScanScreenshotImage.mockRejectedValue(new Error("x"));
    render(<ScreenshotGallery scanId={7} onClose={() => {}} />);
    await waitFor(() => expect(screen.getByText("Could not load")).toBeTruthy());
  });

  it("does nothing while closed", () => {
    render(<ScreenshotGallery scanId={null} onClose={() => {}} />);
    expect(api.getScanScreenshots).not.toHaveBeenCalled();
  });
});
