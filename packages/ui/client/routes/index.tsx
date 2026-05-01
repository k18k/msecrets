import { createFileRoute } from "@tanstack/react-router";
import { AppShellLayout } from "../components/app/AppShellLayout";
import { OverviewView } from "../components/overview/OverviewView";

export const Route = createFileRoute("/")({
  component: RouteComponent,
});

function RouteComponent() {
  return (
    <AppShellLayout>
      {(data, derived) => <OverviewView data={data} derived={derived} />}
    </AppShellLayout>
  );
}
