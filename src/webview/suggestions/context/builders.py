from shared.models.linkage import CVEDerivationClusterProposal
from webview.suggestions.context.types import (
    MaintainerAddContext,
    MaintainerContext,
    MaintainerEditabilityStatus,
    MaintainerListContext,
    PackageListContext,
)


def is_suggestion_editable(suggestion: CVEDerivationClusterProposal) -> bool:
    """Whether packages and maintainers can be edited depending on the suggestion status"""
    return suggestion.status in [
        CVEDerivationClusterProposal.Status.PENDING,
        CVEDerivationClusterProposal.Status.ACCEPTED,
    ]


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
    packages_editable = is_suggestion_editable(suggestion)

    return PackageListContext(
        active=active_packages,
        ignored=ignored_packages,
        editable=packages_editable,
        suggestion_id=suggestion.pk,
    )


def get_maintainer_list_context(
    suggestion: CVEDerivationClusterProposal,
    maintainer_add_error_message: str | None = None,
) -> MaintainerListContext:
    # FIXME(@florent): There is a pydantic model for cached suggestions and
    # categorized maintainers. I'd be nice to use it rather than browse untyped
    # dictionaries.

    # Access categorized maintainers from cached payload dictionary
    categorized_maintainers = suggestion.cached.payload["categorized_maintainers"]

    # Determine if maintainers are editable
    maintainers_editable = is_suggestion_editable(suggestion)

    # Create MaintainerContext objects for each category
    active_contexts = [
        MaintainerContext(
            maintainer=maintainer,
            editability=MaintainerEditabilityStatus.IGNORABLE
            if maintainers_editable
            else MaintainerEditabilityStatus.NON_EDITABLE,
            suggestion_id=suggestion.pk,
        )
        for maintainer in categorized_maintainers["active"]
    ]

    ignored_contexts = [
        MaintainerContext(
            maintainer=maintainer,
            editability=MaintainerEditabilityStatus.RESTORABLE
            if maintainers_editable
            else MaintainerEditabilityStatus.NON_EDITABLE,
            suggestion_id=suggestion.pk,
        )
        for maintainer in categorized_maintainers["ignored"]
    ]

    additional_contexts = [
        MaintainerContext(
            maintainer=maintainer,
            editability=MaintainerEditabilityStatus.DELETABLE
            if maintainers_editable
            else MaintainerEditabilityStatus.NON_EDITABLE,
            suggestion_id=suggestion.pk,
        )
        for maintainer in categorized_maintainers["added"]
    ]

    return MaintainerListContext(
        active=active_contexts,
        ignored=ignored_contexts,
        additional=additional_contexts,
        editable=maintainers_editable,
        suggestion_id=suggestion.pk,
        maintainer_add_context=MaintainerAddContext(maintainer_add_error_message),
    )
