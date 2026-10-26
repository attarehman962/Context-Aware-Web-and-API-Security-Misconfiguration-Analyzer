import { Button } from "@/components/ui/button";
import { publicEnv } from "@/lib/env";

export default function Home() {
  return (
    <div className="flex max-w-3xl flex-col gap-6 py-16">
      <h1 className="font-heading text-3xl font-semibold tracking-tight">
        CAWASMA
      </h1>
      <p className="text-lg text-muted-foreground">
        Context-Aware Web &amp; API Security Misconfiguration Analyzer
      </p>
      <div>
        <Button
          nativeButton={false}
          render={<a href={`${publicEnv.apiUrl}/docs`} />}
        >
          API docs
        </Button>
      </div>
    </div>
  );
}
