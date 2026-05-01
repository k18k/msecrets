import { createFileRoute } from "@tanstack/react-router";
import { AppShellLayout } from "../components/app/AppShellLayout";
import { SecretsView } from "../components/secrets/SecretsView";

export const Route = createFileRoute("/secrets")({
  component: RouteComponent,
});

function RouteComponent() {
  return (
    <AppShellLayout>
      {(data, derived) => <SecretsView data={data} derived={derived} />}
    </AppShellLayout>
  );
}
