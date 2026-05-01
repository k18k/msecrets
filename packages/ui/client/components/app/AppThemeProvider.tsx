import type { ReactNode } from "react";
import { MantineProvider, createTheme } from "@mantine/core";

const theme = createTheme({
  fontFamily:
    "Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif",
  headings: {
    fontWeight: "650",
  },
  primaryColor: "blue",
});

export function AppThemeProvider({ children }: { children: ReactNode }) {
  return <MantineProvider theme={theme}>{children}</MantineProvider>;
}
