import { QueryCache, QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider } from "@tanstack/react-router";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { ApiError, queryKeys } from "@/lib/api";
import { makeRouter } from "@/router";
import "./index.css";

const queryClient: QueryClient = new QueryClient({
  queryCache: new QueryCache({
    onError: (err, query) => {
      // The session expired or was ended elsewhere: back to the login page.
      // Skip the session probe itself and the login/setup pages: route
      // guards expect that 401, and redirecting there would loop.
      const path = router.state.location.pathname;
      const probe = query.queryKey[0] === queryKeys.me[0];
      if (err instanceof ApiError && err.status === 401 && !probe && path !== "/login" && path !== "/setup") {
        queryClient.removeQueries({ queryKey: queryKeys.me });
        void router.navigate({ to: "/login", search: { redirect: router.state.location.href } });
      }
    },
  }),
  defaultOptions: {
    queries: {
      retry: (count, err) => !(err instanceof ApiError && err.status < 500) && count < 2,
    },
  },
});

const router = makeRouter(queryClient);

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  </StrictMode>,
);
