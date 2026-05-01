import { createORPCClient } from "@orpc/client";
import { RPCLink } from "@orpc/client/fetch";
import { createTanstackQueryUtils } from "@orpc/tanstack-query";
import type { RouterClient } from "@orpc/server";
import type { router } from "../server/orpc.ts";

const url = new URL(window.location.href);

url.pathname = "/rpc";
url.search = "";
url.hash = "";
url.username = "";
url.password = "";

const link = new RPCLink({
  url: url.toString(),
});

export const orpcClient: RouterClient<typeof router> = createORPCClient(link);
export const orpc = createTanstackQueryUtils(orpcClient);
