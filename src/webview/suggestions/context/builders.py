from shared.models.linkage import CVEDerivationClusterProposal
from webview.suggestions.context.types import PackageListContext


def get_package_list_context(
    suggestion: CVEDerivationClusterProposal,
) -> PackageListContext:
    # Split packages into active and ignored
    all_packages = suggestion.cached.payload["original_packages"]
    active_packages = suggestion.cached.payload["packages"]
    ignored_packages = {
        k: v for k, v in all_packages.items() if k not in active_packages
    }
    # Determine if packages are editable
    packages_editable = are_packages_editable(suggestion)

    return PackageListContext(
        active=active_packages,
        ignored=ignored_packages,
        editable=packages_editable,
        suggestion_id=suggestion.pk,
    )


def are_packages_editable(suggestion: CVEDerivationClusterProposal) -> bool:
    return suggestion.status in [
        CVEDerivationClusterProposal.Status.PENDING,
        CVEDerivationClusterProposal.Status.ACCEPTED,
    ]
