import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import ToggleSwitch from "./ToggleSwitch";

describe("ToggleSwitch", () => {
  it("reports the new value when clicked", async () => {
    const onChange = vi.fn();
    render(<ToggleSwitch checked={false} onChange={onChange} ariaLabel="Check GitHub" />);
    await userEvent.click(screen.getByRole("checkbox", { name: "Check GitHub" }));
    expect(onChange).toHaveBeenCalledWith(true);
  });

  it("does nothing while disabled", async () => {
    const onChange = vi.fn();
    render(<ToggleSwitch checked disabled onChange={onChange} ariaLabel="Check GitHub" />);
    const box = screen.getByRole("checkbox", { name: "Check GitHub" });
    expect(box).toBeDisabled();
    await userEvent.click(box);
    expect(onChange).not.toHaveBeenCalled();
  });
});
