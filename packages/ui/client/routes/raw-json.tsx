import { createFileRoute } from "@tanstack/react-router";
import { AppShellLayout } from "../components/app/AppShellLayout";
import { RawJsonView } from "../components/raw-json/RawJsonView";

export const Route = createFileRoute("/raw-json")({
  component: RouteComponent,
});

function RouteComponent() {
  return (
    <AppShellLayout>
      {(data, derived) => <RawJsonView data={data} derived={derived} />}
    </AppShellLayout>
  );
}
