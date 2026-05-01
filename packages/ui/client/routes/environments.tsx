import { createFileRoute } from "@tanstack/react-router";
import { AppShellLayout } from "../components/app/AppShellLayout";
import { EnvironmentsView } from "../components/environments/EnvironmentsView";

export const Route = createFileRoute("/environments")({
  component: RouteComponent,
});

function RouteComponent() {
  return (
    <AppShellLayout>
      {(data, derived) => <EnvironmentsView data={data} derived={derived} />}
    </AppShellLayout>
  );
}
