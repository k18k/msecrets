import type { Notice, PanelState } from "./types.ts";

type PageHrefOptions = {
  environment?: string;
  message?: string;
  pathname?: string;
  panel?: PanelState["kind"];
  secret?: string;
  status?: Notice["tone"];
};

function getFirstValue(params: URLSearchParams, key: string): string | undefined {
  const value = params.get(key);

  if (!value) {
    return undefined;
  }

  const normalizedValue = value.trim();
  return normalizedValue ? normalizedValue : undefined;
}

function getSecretOnlyPanel(
  kind: Extract<PanelState["kind"], "rename-secret">,
  params: URLSearchParams,
): PanelState {
  const secret = getFirstValue(params, "secret");

  if (!secret) {
    return { kind: "none" };
  }

  return {
    kind,
    secret,
  };
}

function getSecretPanel(
  kind: Extract<
    PanelState["kind"],
    "peek-secret" | "revoke-secret" | "set-secret" | "share-secret"
  >,
  params: URLSearchParams,
): PanelState {
  const secret = getFirstValue(params, "secret");
  const environment = getFirstValue(params, "environment");

  if (!secret || !environment) {
    return { kind: "none" };
  }

  return {
    environment,
    kind,
    secret,
  };
}

export function getNotice(params: URLSearchParams): Notice | null {
  const message = getFirstValue(params, "message");
  const tone = getFirstValue(params, "status");

  if (!message || !tone) {
    return null;
  }

  if (tone !== "success" && tone !== "error") {
    return null;
  }

  return {
    message,
    tone,
  };
}

export function getPanelState(params: URLSearchParams): PanelState {
  const panel = getFirstValue(params, "panel");

  switch (panel) {
    case "create-secret":
      return { kind: "create-secret" };
    case "rename-secret":
      return getSecretOnlyPanel("rename-secret", params);
    case "peek-secret":
      return getSecretPanel("peek-secret", params);
    case "revoke-secret":
      return getSecretPanel("revoke-secret", params);
    case "set-secret":
      return getSecretPanel("set-secret", params);
    case "share-secret":
      return getSecretPanel("share-secret", params);
    default:
      return { kind: "none" };
  }
}

export function buildPageHref(options: PageHrefOptions = {}): string {
  const params = new URLSearchParams();

  if (options.panel && options.panel !== "none") {
    params.set("panel", options.panel);
  }

  if (options.secret) {
    params.set("secret", options.secret);
  }

  if (options.environment) {
    params.set("environment", options.environment);
  }

  if (options.status) {
    params.set("status", options.status);
  }

  if (options.message) {
    params.set("message", options.message);
  }

  const query = params.toString();
  const pathname = options.pathname ?? "/";
  return query ? `${pathname}?${query}` : pathname;
}
