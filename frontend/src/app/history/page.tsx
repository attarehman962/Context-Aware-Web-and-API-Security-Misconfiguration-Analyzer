import { History } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { EmptyState } from "@/components/empty-state";
import { Button } from "@/components/ui/button";

export const metadata: Metadata = { title: "History · CAWASMA" };

// Placeholder until the history table (GET /api/scans) is built.
export default function HistoryPage() {
  return (
    <>
      <h1 className="font-heading text-2xl font-semibold tracking-tight">
        Scan history
      </h1>
      <EmptyState
        icon={History}
        title="No scans to show yet"
        description="Past scans and their severity totals will be listed here."
        action={
          <Button nativeButton={false} render={<Link href="/" />}>
            Start a new scan
          </Button>
        }
      />
    </>
  );
}
