import { UserMinusIcon, UserPlusIcon } from "lucide-preact";
import type { Maintainer as MaintainerType } from "@/api/generated/models";
import { ExternalLink } from "@/components/ui/ExternalLink";
import { useMaintainerMutation } from "@/hooks/useMaintainer";

type Props = {
  maintainer: MaintainerType;
  suggestionId: number;
  editable: boolean;
  isIgnored: boolean;
};

export function Maintainer({ maintainer, suggestionId, editable, isIgnored }: Props) {
  const mutation = useMaintainerMutation(suggestionId);

  function handleClick() {
    mutation.mutate({
      id: suggestionId,
      data: { github_id: maintainer.github_id, ignored: !isIgnored },
    });
  }

  return (
    <div className="row gap centered">
      {editable && (
        <button
          type="button"
          className={`btn ${isIgnored ? "btn-green" : "btn-gray"} row gap-small centered`}
          onClick={handleClick}
          disabled={mutation.isPending}
        >
          {isIgnored ? <UserPlusIcon size="1em" /> : <UserMinusIcon size="1em" />}
          {isIgnored ? "Restore" : "Ignore"}
        </button>
      )}
      <div>
        <ExternalLink className="bold" href={`https://github.com/${maintainer.github}`}>
          @{maintainer.github}
        </ExternalLink>
        {maintainer.name && <span> {maintainer.name}</span>}
        {maintainer.email && (
          <span>
            {" "}
            &lt;
            <a href={`mailto:${maintainer.email}`}>{maintainer.email}</a>
            &gt;
          </span>
        )}
      </div>
    </div>
  );
}
