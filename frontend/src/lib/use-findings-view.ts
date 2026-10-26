"use client";

import { useSearchParams } from "next/navigation";
import { useCallback, useMemo, useState } from "react";

import { parseView, serializeView, type FindingsView } from "./findings";

/**
 * Ranking and filters of the findings list, stored in the URL query so a
 * filtered view can be shared and survives a reload.
 *
 * The view lives in state so inputs update at once; each change is written
 * to the URL with `history.replaceState` (Next.js syncs that into
 * useSearchParams without a server round trip, which router.replace on this
 * dynamic route would cost). When the URL changes from elsewhere (back /
 * forward, an edited link) the state follows it.
 */
export function useFindingsView(): [
  FindingsView,
  (view: FindingsView) => void,
] {
  const searchParams = useSearchParams();
  const query = searchParams.toString();
  const urlView = useMemo(() => parseView(new URLSearchParams(query)), [query]);

  const [state, setState] = useState({ view: urlView, query });
  if (state.query !== query) {
    setState({ view: urlView, query });
  }

  const setView = useCallback((next: FindingsView) => {
    setState((s) => ({ ...s, view: next }));
    const params = serializeView(
      next,
      new URLSearchParams(window.location.search),
    );
    const search = params.toString();
    window.history.replaceState(
      window.history.state,
      "",
      `${window.location.pathname}${search ? `?${search}` : ""}`,
    );
  }, []);

  return [state.view, setView];
}
