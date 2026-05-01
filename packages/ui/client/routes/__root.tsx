import "@mantine/core/styles.css";
import { Outlet, createRootRouteWithContext } from "@tanstack/react-router";
import type { QueryClient } from "@tanstack/react-query";

import { AppThemeProvider } from "../components/app/AppThemeProvider";
import type { orpc, orpcClient } from "../orpc-client";

export const Route = createRootRouteWithContext<{
  queryClient: QueryClient;
  orpc: typeof orpc;
  orpcClient: typeof orpcClient;
}>()({
  component: RootComponent,
});

function RootComponent() {
  return (
    <AppThemeProvider>
      <Outlet />
    </AppThemeProvider>
  );
}
