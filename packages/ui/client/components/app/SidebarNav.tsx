import { AppShell, Badge, NavLink, ScrollArea, Stack } from "@mantine/core";
import { Link, useLocation } from "@tanstack/react-router";
import {
  IconAlertTriangle,
  IconBraces,
  IconDashboard,
  IconKey,
  IconLayersIntersect,
  IconLock,
} from "@tabler/icons-react";

import type { DerivedSecretsFileState } from "../../hooks/useDerivedSecretsFileState";

const navItems = [
  { icon: IconDashboard, label: "Overview", to: "/" },
  { icon: IconLock, label: "Secrets", to: "/secrets" },
  { icon: IconLayersIntersect, label: "Environments", to: "/environments" },
  { icon: IconKey, label: "Recipient Keys", to: "/keys" },
  { icon: IconKey, label: "Runtime Keys", to: "/runtime-keys" },
  { icon: IconBraces, label: "Raw JSON", to: "/raw-json" },
  { icon: IconAlertTriangle, label: "Diagnostics", to: "/diagnostics" },
] as const;

export function SidebarNav({ derived }: { derived: DerivedSecretsFileState }) {
  const location = useLocation();

  function rightSection(to: string) {
    if (to === "/secrets") {
      return <Badge size="sm">{derived.secretCount}</Badge>;
    }

    if (to === "/environments") {
      return <Badge size="sm">{derived.environmentCount}</Badge>;
    }

    if (to === "/keys") {
      return <Badge size="sm">{derived.keysCount}</Badge>;
    }

    if (to === "/diagnostics") {
      const count = derived.errorCount + derived.warningCount;
      return count ? (
        <Badge color={derived.errorCount ? "red" : "yellow"} size="sm">
          {count}
        </Badge>
      ) : null;
    }

    return null;
  }

  return (
    <AppShell.Navbar p="xs">
      <ScrollArea>
        <Stack gap={4}>
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                active={location.pathname === item.to}
                component={Link}
                key={item.to}
                label={item.label}
                leftSection={<Icon size={16} />}
                rightSection={rightSection(item.to)}
                to={item.to}
              />
            );
          })}
        </Stack>
      </ScrollArea>
    </AppShell.Navbar>
  );
}
