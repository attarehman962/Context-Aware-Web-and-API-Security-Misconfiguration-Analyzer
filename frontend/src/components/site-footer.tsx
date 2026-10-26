import { ApiModeIndicator } from "@/components/api-mode";

export function SiteFooter() {
  return (
    <footer className="border-t">
      <div className="mx-auto flex w-full max-w-6xl flex-wrap items-center justify-between gap-3 px-4 py-4 text-sm text-muted-foreground sm:px-6">
        <p>CAWASMA: context-aware scores are not official CVSS v3.1 scores.</p>
        <ApiModeIndicator />
      </div>
    </footer>
  );
}
