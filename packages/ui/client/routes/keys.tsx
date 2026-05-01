import { createFileRoute } from "@tanstack/react-router";
import { AppShellLayout } from "../components/app/AppShellLayout";
import { RecipientKeysView } from "../components/keys/RecipientKeysView";

export const Route = createFileRoute("/keys")({
  component: RouteComponent,
});

function RouteComponent() {
  return (
    <AppShellLayout>
      {(data, derived) => <RecipientKeysView data={data} derived={derived} />}
    </AppShellLayout>
  );
}
