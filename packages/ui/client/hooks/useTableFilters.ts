import { useMemo, useState } from "react";

export type SecretTableFilters = {
  environment: string | null;
  issueOnly: boolean;
  missingOnly: boolean;
  owner: string | null;
  search: string;
};

export function useTableFilters() {
  const [search, setSearch] = useState("");
  const [environment, setEnvironment] = useState<string | null>(null);
  const [owner, setOwner] = useState<string | null>(null);
  const [missingOnly, setMissingOnly] = useState(false);
  const [issueOnly, setIssueOnly] = useState(false);

  return useMemo(
    () => ({
      filters: {
        environment,
        issueOnly,
        missingOnly,
        owner,
        search,
      },
      setEnvironment,
      setIssueOnly,
      setMissingOnly,
      setOwner,
      setSearch,
    }),
    [environment, issueOnly, missingOnly, owner, search],
  );
}
