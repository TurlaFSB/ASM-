import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import ToastProvider from "./Toast";
import { useToast } from "./toastContext";

function Trigger({ action }) {
  const { toast } = useToast();
  return <button onClick={() => toast("Saved", "ok", action)}>go</button>;
}

describe("Toast", () => {
  it("shows a message in a polite live region and can be dismissed", async () => {
    render(<ToastProvider><Trigger /></ToastProvider>);
    await userEvent.click(screen.getByText("go"));
    expect(screen.getByRole("status")).toHaveTextContent("Saved");
    await userEvent.click(screen.getByRole("button", { name: "Dismiss" }));
    expect(screen.queryByText("Saved")).not.toBeInTheDocument();
  });

  it("runs the action and then closes", async () => {
    const onClick = vi.fn();
    render(<ToastProvider><Trigger action={{ label: "Undo", onClick }} /></ToastProvider>);
    await userEvent.click(screen.getByText("go"));
    await userEvent.click(screen.getByRole("button", { name: "Undo" }));
    expect(onClick).toHaveBeenCalledTimes(1);
    expect(screen.queryByText("Saved")).not.toBeInTheDocument();
  });
});
