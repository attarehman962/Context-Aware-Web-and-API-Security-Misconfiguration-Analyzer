// Accessibility: axe (WCAG 2.1 A/AA) on every page and state, in light and
// dark mode, plus keyboard and phone-width checks. Runs against the mock
// build (`npm run test:e2e`), so every page has data.
import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

const DONE = "/scans/11111111-1111-4111-8111-111111111111";
const RUNNING = "/scans/22222222-2222-4222-8222-222222222222";
const FAILED = "/scans/44444444-4444-4444-8444-444444444444";
const UNKNOWN = "/scans/99999999-9999-4999-8999-999999999999";
const LARGE = "/scans/55555555-5555-4555-8555-555555555555";

const PAGES: {
  name: string;
  path: string;
  ready: (page: Page) => Promise<void>;
}[] = [
  {
    name: "new scan",
    path: "/",
    ready: (p) => p.getByLabel("Target URL").waitFor(),
  },
  {
    name: "history",
    path: "/history",
    ready: (p) => p.locator("tbody tr").first().waitFor(),
  },
  {
    name: "evaluation",
    path: "/evaluation",
    // Open every "Show the numbers" table so axe checks those too.
    ready: async (p) => {
      await p.getByRole("heading", { level: 1, name: "Evaluation" }).waitFor();
      await p.evaluate(() =>
        document.querySelectorAll("details").forEach((d) => (d.open = true)),
      );
    },
  },
  {
    name: "results",
    path: DONE,
    ready: (p) => p.getByRole("heading", { name: "Findings" }).waitFor(),
  },
  {
    name: "running scan",
    path: RUNNING,
    ready: (p) => p.getByRole("progressbar").first().waitFor(),
  },
  {
    name: "failed scan",
    path: FAILED,
    ready: (p) => p.getByText("The scan failed").waitFor(),
  },
  {
    name: "unknown scan",
    path: UNKNOWN,
    ready: (p) => p.getByRole("heading", { name: "Scan not found" }).waitFor(),
  },
  {
    name: "large scan",
    path: LARGE,
    ready: (p) => p.getByRole("heading", { name: "Findings" }).waitFor(),
  },
];

async function expectNoViolations(page: Page) {
  const { violations } = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  const readable = violations.map((v) => ({
    rule: v.id,
    impact: v.impact,
    help: v.help,
    // Selector, the element and why it failed (e.g. the contrast ratio).
    nodes: v.nodes
      .slice(0, 3)
      .map(
        (n) =>
          `${n.target.join(" ")} :: ${n.html.slice(0, 160)} :: ${n.failureSummary?.split("\n")[1] ?? ""}`,
      ),
  }));
  expect(readable).toEqual([]);
}

for (const scheme of ["light", "dark"] as const) {
  test.describe(`axe, ${scheme} mode`, () => {
    test.use({ colorScheme: scheme });
    for (const { name, path, ready } of PAGES) {
      test(name, async ({ page }) => {
        await page.goto(path);
        await ready(page);
        await expectNoViolations(page);
      });
    }

    test("results with a finding open, filters set and the export menu", async ({
      page,
    }) => {
      await page.goto(`${DONE}?severity=CRITICAL,HIGH`);
      await page
        .getByRole("button", { name: /Why this score\?.*CKI-003/ })
        .click();
      await page.getByText("CVSS v3.1 vector").first().waitFor();
      await expectNoViolations(page);
      await page.getByRole("button", { name: /Export/ }).click();
      await page.getByRole("menuitem", { name: /PDF report/ }).waitFor();
      await expectNoViolations(page);
    });

    test("new scan with validation errors and advanced options", async ({
      page,
    }) => {
      await page.goto("/");
      await page.getByLabel("Target URL").fill("http://example.com");
      await page.getByRole("checkbox", { name: /I own this target/ }).check();
      await page.getByRole("button", { name: "Start scan" }).click();
      await page.getByText(/Only HTTPS targets/).waitFor();
      await page.getByText("Advanced options").click();
      await expectNoViolations(page);
    });
  });
}

test.describe("keyboard", () => {
  test("skip link moves focus to the main content", async ({ page }) => {
    await page.goto("/history");
    await page.keyboard.press("Tab");
    const skip = page.getByRole("link", { name: "Skip to content" });
    await expect(skip).toBeFocused();
    await expect(skip).toBeVisible();
    await page.keyboard.press("Enter");
    await expect(page.locator("main")).toBeFocused();
  });

  test("a scan can be started and its results explored with the keyboard only", async ({
    page,
  }) => {
    await page.goto(DONE);
    await page.getByRole("heading", { name: "Findings" }).waitFor();
    // The button's label changes once open, so find it by its row.
    const why = page.locator(
      'article[data-check-id="INF-007"] button[aria-expanded]',
    );
    await why.focus();
    await page.keyboard.press("Enter");
    await expect(why).toHaveAttribute("aria-expanded", "true");
    const chainLink = page.getByRole("link", { name: /HDR-007/ });
    await chainLink.focus();
    await page.keyboard.press("Enter");
    await expect(
      page.locator('article[data-check-id="HDR-007"]'),
    ).toBeFocused();
  });

  test("every focused control shows a focus ring", async ({ page }) => {
    await page.goto(DONE);
    await page.getByRole("heading", { name: "Findings" }).waitFor();
    for (let i = 0; i < 25; i += 1) {
      await page.keyboard.press("Tab");
      const visible = await page.evaluate(() => {
        const el = document.activeElement as HTMLElement | null;
        if (!el || el === document.body) return true;
        const style = getComputedStyle(el);
        const ring =
          style.outlineStyle !== "none" && parseFloat(style.outlineWidth) > 0;
        const shadow = style.boxShadow !== "none";
        return ring || shadow;
      });
      expect(visible, `focus ring on tab stop ${i + 1}`).toBe(true);
    }
  });
});

test.describe("phone width", () => {
  test.use({
    viewport: { width: 360, height: 740 },
    isMobile: true,
    hasTouch: true,
  });
  for (const { name, path, ready } of PAGES) {
    test(`${name} has no horizontal scroll`, async ({ page }) => {
      await page.goto(path);
      await ready(page);
      const overflow = await page.evaluate(
        () =>
          document.documentElement.scrollWidth -
          document.documentElement.clientWidth,
      );
      expect(overflow).toBeLessThanOrEqual(0);
    });
  }
});
