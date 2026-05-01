import { useQuery } from "@tanstack/react-query";

import type { WorkspacePageData } from "../../server/lib/types.ts";
import { orpcClient } from "../orpc-client";
import { queryKeys } from "./queryKeys";

export function useSecretsFileQuery() {
  return useQuery<WorkspacePageData>({
    queryFn: () => orpcClient.workspace.get(),
    queryKey: queryKeys.workspace,
  });
}
