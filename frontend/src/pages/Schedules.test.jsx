import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../api", () => ({
  getSchedules: vi.fn(), createSchedule: vi.fn(), setScheduleEnabled: vi.fn(),
  deleteSchedule: vi.fn(), getTargets: vi.fn(),
}));

import * as api from "../api";
import ToastProvider from "../components/Toast";
import Schedules from "./Schedules";

const future = new Date(Date.now() + 3 * 3600 * 1000).toISOString();
const sched = (over = {}) => ({ id: 7, target_id: 1, preset: "daily", cron_expression: "0 0 * * *",
  enabled: true, next_run_at: future, last_run_at: null, ...over });

function setup(schedules) {
  api.getSchedules.mockResolvedValue({ data: schedules });
  api.getTargets.mockResolvedValue({ data: [{ id: 1, domain: "acme.com" }] });
  return render(<ToastProvider><Schedules /></ToastProvider>);
}

beforeEach(() => vi.clearAllMocks());

describe("Schedules switch", () => {
  it("pauses an enabled schedule by sending enabled=false, then reloads", async () => {
    api.setScheduleEnabled.mockResolvedValue({ data: {} });
    setup([sched({ enabled: true })]);
    await userEvent.click(await screen.findByRole("checkbox", { name: "Enabled for acme.com" }));
    await waitFor(() => expect(api.setScheduleEnabled).toHaveBeenCalledWith(7, false));
    await waitFor(() => expect(api.getSchedules).toHaveBeenCalledTimes(2));
  });

  it("resumes a paused schedule by sending enabled=true", async () => {
    api.setScheduleEnabled.mockResolvedValue({ data: {} });
    setup([sched({ enabled: false })]);
    expect(await screen.findByText("Paused")).toBeTruthy();
    await userEvent.click(screen.getByRole("checkbox", { name: "Enabled for acme.com" }));
    await waitFor(() => expect(api.setScheduleEnabled).toHaveBeenCalledWith(7, true));
  });

  it("tells the user when the change could not be saved", async () => {
    api.setScheduleEnabled.mockRejectedValue(new Error("boom"));
    setup([sched()]);
    await userEvent.click(await screen.findByRole("checkbox", { name: "Enabled for acme.com" }));
    expect(await screen.findByText("Could not change the schedule.")).toBeTruthy();
  });
});
