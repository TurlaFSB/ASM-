import "@testing-library/jest-dom/vitest";
import { afterEach } from "vitest";
import { cleanup } from "@testing-library/react";

afterEach(() => cleanup());

// jsdom has no <dialog> behaviour; the side panel (Sheet) uses showModal/close.
if (typeof HTMLDialogElement !== "undefined") {
  HTMLDialogElement.prototype.showModal ||= function showModal() { this.setAttribute("open", ""); };
  HTMLDialogElement.prototype.close ||= function close() { this.removeAttribute("open"); this.dispatchEvent(new Event("close")); };
}
