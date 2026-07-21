import { useEffect, useRef, useState } from "react";

/**
 * Sondage périodique optimisé :
 * - se met en pause quand l'onglet navigateur est en arrière-plan (visibilité) ;
 * - `enabled` (défaut true) permet de ne sonder une donnée lourde que lorsque son
 *   onglet est actif, puis reprend immédiatement au retour.
 */
export function usePolling<T>(fn: () => Promise<T>, intervalMs: number, enabled = true) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const fnRef = useRef(fn);
  fnRef.current = fn;
  useEffect(() => {
    if (!enabled) return;
    let alive = true;
    const tick = async () => {
      if (typeof document !== "undefined" && document.hidden) return; // pas de trafic en arrière-plan
      try {
        const d = await fnRef.current();
        if (alive) {
          setData(d);
          setError(null);
        }
      } catch (e) {
        if (alive) setError(String(e));
      }
    };
    tick();
    const id = setInterval(tick, intervalMs);
    const onVis = () => { if (!document.hidden) tick(); }; // reprise immédiate au retour au premier plan
    document.addEventListener("visibilitychange", onVis);
    return () => {
      alive = false;
      clearInterval(id);
      document.removeEventListener("visibilitychange", onVis);
    };
  }, [intervalMs, enabled]);
  return { data, error };
}
