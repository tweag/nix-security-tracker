import { ChevronDownIcon, ChevronRightIcon } from "lucide-preact";
import { useState } from "preact/hooks";
import type { Match, SuggestionMatchingAffectedProducts } from "@/api/generated/models";
import { InlineIcon } from "@/components/ui/InlineIcon";
import { cx } from "@/utils/className";
import { cveFieldLabel, mappingLabel, matcherLabel, pkgFieldLabel } from "./labels";
import styles from "./Matching.module.css";

type Props = {
  attrpath: string;
  matches: Match[];
  affectedProducts: SuggestionMatchingAffectedProducts;
};

function productName(products: SuggestionMatchingAffectedProducts, id: number | null): string {
  if (id === null) return "";
  const product = products[String(id)];
  if (!product) return "";
  const name = product.product ?? product.package_name ?? product.repo ?? "";
  return product.vendor ? `${product.vendor}/${name}` : name;
}

/** One sentence of evidence: which CVE field and value matched which package field and value. */
function Evidence({
  match,
  affectedProducts,
}: {
  match: Match;
  affectedProducts: SuggestionMatchingAffectedProducts;
}) {
  const { evidence } = match;
  const product = productName(affectedProducts, evidence.affected_product);
  // The same hit through further products, named only where the name differs: the
  // kernel's git and semver products are both "linux/linux" and add nothing to read.
  const alsoFrom = [
    ...new Set(
      evidence.affected_products
        .filter((id) => id !== evidence.affected_product)
        .map((id) => productName(affectedProducts, id))
        .filter((name) => name && name !== product),
    ),
  ];
  return (
    <li className={cx((match.retracted || match.vetoed) && "text-gray")}>
      <strong>{matcherLabel(match.matcher, evidence)}</strong>{" "}
      <span className="text-gray">
        ({match.matcher} v{match.matcher_version}, score {match.score.toFixed(2)} × weight{" "}
        {match.weight.toFixed(2)})
      </span>
      {": "}
      {evidence.mapping ? (
        <>
          mapping <span className="monospace">{mappingLabel(evidence.mapping)}</span>
          {evidence.mapping.id !== null && (
            <span className="text-gray"> #{evidence.mapping.id}</span>
          )}
          {evidence.pkg_field === "attr_glob" && <>, glob expanded to this attribute</>}
          {product && <span className="text-gray"> ({product})</span>}
        </>
      ) : evidence.provenance_flags !== null ? (
        <>
          backfilled from a link of the old matcher
          {evidence.cve_fields.length > 0 && (
            <>, which matched on the CVE {evidence.cve_fields.map(cveFieldLabel).join(", ")}</>
          )}{" "}
          <span className="text-gray">(provenance flags {evidence.provenance_flags})</span>
        </>
      ) : (
        <>
          {evidence.cve_field ? (
            <>
              CVE {cveFieldLabel(evidence.cve_field)}{" "}
              <span className="monospace">{evidence.cve_value}</span>
              {(product || evidence.container) && (
                <span className="text-gray">
                  {" "}
                  ({[product, evidence.container].filter(Boolean).join(", ")})
                </span>
              )}
            </>
          ) : (
            "CVE"
          )}{" "}
          matched{" "}
          {evidence.pkg_field ? (
            <>
              {pkgFieldLabel(evidence.pkg_field)}{" "}
              <span className="monospace">{evidence.pkg_value}</span>
            </>
          ) : (
            "the package"
          )}
        </>
      )}
      {evidence.similarity != null && <>, similarity {evidence.similarity.toFixed(2)}</>}
      {evidence.branches.length > 0 && <>, on {evidence.branches.join(", ")}</>}
      {evidence.other_hits > 0 && <> (+{evidence.other_hits} other reasons)</>}
      {alsoFrom.length > 0 && <>, also through {alsoFrom.join(", ")}</>}
      {match.retracted && <> — retracted</>}
      {match.vetoed && <> — vetoed by a mapping, does not count</>}
    </li>
  );
}

/**
 * One chip per contributing matcher, each expanding to its evidence.
 * Retracted and vetoed matches are listed struck through.
 */
export function Provenance({ attrpath, matches, affectedProducts }: Props) {
  const [open, setOpen] = useState<Set<string>>(new Set());

  function toggle(matcher: string) {
    setOpen((prev) => {
      const next = new Set(prev);
      if (next.has(matcher)) next.delete(matcher);
      else next.add(matcher);
      return next;
    });
  }

  const shown = matches.filter((m) => open.has(m.matcher));

  return (
    <div className="column gap-small">
      <div className="row gap-small wrap">
        {matches.map((m) => (
          <button
            key={m.matcher}
            type="button"
            className={cx(
              "tag tag-gray cursor-pointer no-line-breaks",
              (m.retracted || m.vetoed) && styles.retracted,
            )}
            aria-expanded={open.has(m.matcher)}
            title={`${m.matcher}: ${m.vetoed ? "vetoed, contributes nothing" : `contributes ${m.contribution.toFixed(2)}`}${m.retracted ? " (retracted)" : ""}`}
            onClick={() => toggle(m.matcher)}
            data-testid={`provenance-${attrpath}-${m.matcher}`}
          >
            <InlineIcon icon={open.has(m.matcher) ? ChevronDownIcon : ChevronRightIcon} />
            {matcherLabel(m.matcher, m.evidence)}
          </button>
        ))}
      </div>
      {shown.length > 0 && (
        <ul className={styles.evidence} data-testid={`evidence-${attrpath}`}>
          {shown.map((m) => (
            <Evidence key={m.matcher} match={m} affectedProducts={affectedProducts} />
          ))}
        </ul>
      )}
    </div>
  );
}
