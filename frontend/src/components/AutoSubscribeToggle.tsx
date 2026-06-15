import { useQueryClient } from "@tanstack/react-query";
import {
  getGetAutoSubscribeQueryKey,
  useGetAutoSubscribe,
  useSetAutoSubscribe,
} from "../api/generated/endpoints";

export function AutoSubscribeToggle() {
  const queryClient = useQueryClient();

  const { data, isLoading, isError } = useGetAutoSubscribe();

  const { mutate, isPending } = useSetAutoSubscribe({
    mutation: {
      onSuccess: () => {
        queryClient.invalidateQueries({
          queryKey: getGetAutoSubscribeQueryKey(),
        });
      },
    },
  });

  if (isLoading) return <p>Loading subscription preferences...</p>;
  if (isError) return <p>Failed to load subscription preferences.</p>;

  const enabled = data?.enabled ?? false;

  return (
    <label>
      <input
        type="checkbox"
        checked={enabled}
        disabled={isPending}
        onChange={() => mutate({ data: { enabled: !enabled } })}
      />
      Auto-subscribe to maintained packages
      {isPending && <span> (saving...)</span>}
    </label>
  );
}
