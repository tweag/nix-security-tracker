import type { RefObject } from "preact";
import { useEffect, useState } from "preact/hooks";

/**
 * Whether the element is in or near (within `margin`) the viewport; stays true once it was,
 * so that a query enabled by it is not dropped when the user scrolls on.
 * Without `IntersectionObserver` support, true at once.
 */
export function useNearViewport(ref: RefObject<Element>, margin = "600px"): boolean {
  const [near, setNear] = useState(false);
  useEffect(() => {
    const element = ref.current;
    if (near || !element) return;
    if (typeof IntersectionObserver === "undefined") {
      setNear(true);
      return;
    }
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries.some((entry) => entry.isIntersecting)) setNear(true);
      },
      { rootMargin: margin },
    );
    observer.observe(element);
    return () => observer.disconnect();
  }, [ref, margin, near]);
  return near;
}
