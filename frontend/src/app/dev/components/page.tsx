import type { Metadata } from "next";
import { notFound } from "next/navigation";

import { publicEnv } from "@/lib/env";

import { ComponentGallery } from "./gallery";

export const metadata: Metadata = {
  title: "Components · CAWASMA",
  robots: { index: false },
};

/** Every shared component in every state, for visual checks (dev only). */
export default function DevComponentsPage() {
  if (!publicEnv.showDevPages) notFound();
  return <ComponentGallery />;
}
