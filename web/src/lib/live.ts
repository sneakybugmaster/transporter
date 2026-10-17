import { useQueryClient } from "@tanstack/react-query";
import { useEffect } from "react";

import { queryKeys } from "./api";

/**
 * useLiveUpdates subscribes to the coordinator's event stream and refetches
 * mesh data whenever nodes join, leave or change. EventSource reconnects on
 * its own after network errors.
 */
export function useLiveUpdates() {
  const qc = useQueryClient();
  useEffect(() => {
    if (typeof EventSource === "undefined") return;
    const es = new EventSource("/api/v1/events");
    const refresh = () => {
      void qc.invalidateQueries({ queryKey: queryKeys.nodes });
      void qc.invalidateQueries({ queryKey: queryKeys.stats });
      // Enrolling a node uses up an auth key.
      void qc.invalidateQueries({ queryKey: queryKeys.authKeys });
      void qc.invalidateQueries({ queryKey: queryKeys.topology });
      void qc.invalidateQueries({ queryKey: queryKeys.audit });
    };
    es.addEventListener("change", refresh);
    // After a reconnect we may have missed events.
    es.addEventListener("open", refresh);
    return () => es.close();
  }, [qc]);
}
