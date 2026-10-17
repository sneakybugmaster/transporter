import type { ErrorComponentProps } from "@tanstack/react-router";
import { RotateCw, TriangleAlert } from "lucide-react";

import { Button } from "@/components/ui/button";

/** ErrorScreen is shown when a page fails to load, e.g. the coordinator is unreachable. */
export function ErrorScreen({ error, reset }: ErrorComponentProps) {
  return (
    <div className="flex min-h-svh items-center justify-center p-4">
      <div role="alert" className="max-w-md space-y-4 text-center">
        <TriangleAlert className="mx-auto size-8 text-destructive" />
        <h1 className="text-lg font-semibold">Can't reach the coordinator</h1>
        <p className="text-sm text-muted-foreground">{error instanceof Error ? error.message : String(error)}</p>
        <Button
          variant="outline"
          onClick={() => {
            reset();
            window.location.reload();
          }}
        >
          <RotateCw /> Try again
        </Button>
      </div>
    </div>
  );
}
