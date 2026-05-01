import { useMutation, useQueryClient } from "@tanstack/react-query";

import { queryKeys } from "./queryKeys";

export function useOrpcMutation<TInput, TOutput>({
  invalidateRuntimeKeys,
  mutationFn,
  onSuccess,
}: {
  invalidateRuntimeKeys?: boolean;
  mutationFn: (input: TInput) => Promise<TOutput>;
  onSuccess?: (result: TOutput) => void;
}) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn,
    onSuccess: async (result) => {
      await queryClient.invalidateQueries({ queryKey: queryKeys.workspace });

      if (invalidateRuntimeKeys) {
        await queryClient.invalidateQueries({ queryKey: queryKeys.runtimeKeys });
      }

      onSuccess?.(result);
    },
  });
}
