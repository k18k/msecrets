import { createFileRoute } from "@tanstack/react-router";
import { AppShellLayout } from "../components/app/AppShellLayout";
import { RuntimeKeysView } from "../components/runtime-keys/RuntimeKeysView";

export const Route = createFileRoute("/runtime-keys")({
  component: RouteComponent,
});

function RouteComponent() {
  return <AppShellLayout>{(data) => <RuntimeKeysView data={data} />}</AppShellLayout>;
}
