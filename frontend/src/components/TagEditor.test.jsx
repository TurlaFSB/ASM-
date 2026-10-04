import { describe, it, expect, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

vi.mock("../api", () => ({ updateTargetTags: vi.fn() }));
import * as api from "../api";
import TagEditor from "./TagEditor";
import { parseTags } from "../lib/tags";

describe("TagEditor", () => {
  it("parses comma separated input", () => {
    expect(parseTags(" prod, team-a ;; ,eu ")).toEqual(["prod", "team-a", "eu"]);
  });

  it("saves and reports the stored tags", async () => {
    api.updateTargetTags.mockResolvedValue({ data: { id: 3, tags: ["prod"] } });
    const onSaved = vi.fn();
    render(<TagEditor target={{ id: 3, domain: "a.io", tags: [] }} onSaved={onSaved} onCancel={() => {}} />);
    await userEvent.type(screen.getByLabelText("Tags for a.io"), "Prod");
    await userEvent.click(screen.getByRole("button", { name: "Save tags" }));
    await waitFor(() => expect(onSaved).toHaveBeenCalledWith({ id: 3, tags: ["prod"] }));
    expect(api.updateTargetTags).toHaveBeenCalledWith(3, ["Prod"]);
  });

  it("shows the server's message for an invalid tag", async () => {
    api.updateTargetTags.mockRejectedValue({ response: { data: { detail: [{ msg: "Value error, 'a/b' is not a valid tag." }] } } });
    render(<TagEditor target={{ id: 3, domain: "a.io" }} onSaved={() => {}} onCancel={() => {}} />);
    await userEvent.type(screen.getByLabelText("Tags for a.io"), "a/b");
    await userEvent.click(screen.getByRole("button", { name: "Save tags" }));
    expect((await screen.findByRole("alert")).textContent).toContain("'a/b' is not a valid tag.");
  });
});
