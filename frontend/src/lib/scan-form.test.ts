import { describe, expect, it } from "vitest";

import {
  DEFAULT_SCAN_FORM,
  submitErrors,
  toScanRequest,
  validateTargetUrl,
} from "./scan-form";

describe("validateTargetUrl", () => {
  it.each([
    "https://shop.example.com",
    "https://shop.example.com/api/v1",
    "  https://shop.example.com  ",
    "https://shop.example.com:8443/",
    "https://localhost",
    "https://[2001:db8::1]/",
    // Single-label hosts: the backend decides (the demo target is one).
    "https://demo-target:8443/",
    "https://intranet",
  ])("accepts %s", (url) => {
    expect(validateTargetUrl(url)).toBeNull();
  });

  it.each([
    ["", /Enter the URL/],
    ["   ", /Enter the URL/],
    [
      "shop.example.com",
      /Include the scheme, for example https:\/\/shop\.example\.com/,
    ],
    ["shop.example.com:8443", /Include the scheme/],
    [
      "http://shop.example.com",
      /Only HTTPS targets can be scanned\. Try https:\/\/shop\.example\.com$/,
    ],
    ["http://shop.example.com/api", /Try https:\/\/shop\.example\.com\/api$/],
    ["ftp://files.example.com", /Only web addresses/],
    ["javascript:alert(1)", /Only web addresses/],
    ["https://", /not a valid URL/],
    ["https://user:secret@shop.example.com", /user name or password/],
  ])("rejects %j", (url, message) => {
    expect(validateTargetUrl(url)).toMatch(message);
  });
});

describe("toScanRequest", () => {
  it("sends the contract field names, trimmed URL and options", () => {
    expect(
      toScanRequest({
        ...DEFAULT_SCAN_FORM,
        url: " https://shop.example.com ",
        authorisation_confirmed: true,
        crawl_depth: 1,
      }),
    ).toEqual({
      url: "https://shop.example.com",
      authorisation_confirmed: true,
      crawl_depth: 1,
      use_wordlist: true,
      passive_only: false,
    });
  });
});

describe("submitErrors", () => {
  it("puts INVALID_TARGET on the URL field", () => {
    expect(
      submitErrors({
        kind: "client",
        status: 400,
        code: "INVALID_TARGET",
        message: "Private addresses are not allowed.",
      }),
    ).toEqual({ fields: { url: "Private addresses are not allowed." } });
  });

  it("maps 422 details to their fields", () => {
    expect(
      submitErrors({
        kind: "client",
        status: 422,
        code: "VALIDATION_ERROR",
        message: "Request validation failed.",
        details: [
          {
            loc: ["body", "authorisation_confirmed"],
            msg: "Input should be True",
            type: "literal_error",
          },
          {
            loc: ["body", "crawl_depth"],
            msg: "Input should be 1 or 2",
            type: "literal_error",
          },
        ],
      }).fields,
    ).toEqual({
      authorisation_confirmed: "Input should be True",
      crawl_depth: "Input should be 1 or 2",
    });
  });

  it("shows network and server errors at form level", () => {
    expect(
      submitErrors({ kind: "network", message: "Could not reach the API." })
        .form?.title,
    ).toMatch(/Can't reach/);
    expect(
      submitErrors({
        kind: "server",
        status: 500,
        code: "INTERNAL_ERROR",
        message: "An internal error occurred.",
      }).form?.title,
    ).toMatch(/could not start the scan/);
  });
});
