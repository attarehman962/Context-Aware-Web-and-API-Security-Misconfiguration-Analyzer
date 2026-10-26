import { NewScanForm } from "@/components/new-scan-form";

export default function NewScanPage() {
  return (
    <div className="flex w-full max-w-2xl flex-col gap-6">
      <div className="flex flex-col gap-2">
        <h1 className="font-heading text-3xl font-semibold tracking-tight">
          New scan
        </h1>
        <p className="text-muted-foreground">
          Find security misconfigurations in a web app or REST API, ranked by
          how much they matter where they occur. Scans are black-box and use
          only safe, read-only requests.
        </p>
      </div>
      <NewScanForm />
    </div>
  );
}
