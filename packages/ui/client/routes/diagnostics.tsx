import { createFileRoute } from "@tanstack/react-router";
import { AppShellLayout } from "../components/app/AppShellLayout";
import { DiagnosticsView } from "../components/diagnostics/DiagnosticsView";

export const Route = createFileRoute("/diagnostics")({
  component: RouteComponent,
});

function RouteComponent() {
  return (
    <AppShellLayout>{(_data, derived) => <DiagnosticsView derived={derived} />}</AppShellLayout>
  );
}
