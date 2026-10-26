"use client";

import { Monitor, Moon, Sun } from "lucide-react";
import { useTheme } from "next-themes";
import { useSyncExternalStore } from "react";

import { Button } from "@/components/ui/button";

const NEXT = { system: "light", light: "dark", dark: "system" } as const;
const ICON = { system: Monitor, light: Sun, dark: Moon } as const;
type Theme = keyof typeof NEXT;

const noop = () => () => {};

/** Cycles system -> light -> dark. */
export function ThemeToggle() {
  const { theme, setTheme } = useTheme();
  // The stored theme is only known in the browser; render a neutral button
  // on the server so hydration matches.
  const mounted = useSyncExternalStore(
    noop,
    () => true,
    () => false,
  );
  const current: Theme =
    mounted && theme && theme in NEXT ? (theme as Theme) : "system";
  const Icon = ICON[current];

  return (
    <Button
      variant="ghost"
      size="icon"
      onClick={() => setTheme(NEXT[current])}
      aria-label={`Theme: ${current}. Switch to ${NEXT[current]}`}
      title={`Theme: ${current}`}
    >
      <Icon aria-hidden />
    </Button>
  );
}
