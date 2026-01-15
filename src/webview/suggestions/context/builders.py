from shared.models.linkage import CVEDerivationClusterProposal, PackageEdit
from webview.suggestions.context.types import PackageListContext


def get_package_list_context(
    suggestion: CVEDerivationClusterProposal,
) -> PackageListContext:
    # Split packages into active and ignored
    all_packages = suggestion.cached.payload["original_packages"]
    ignored_package_attrs = set(
        edit.package_attribute
        # FIXME(@florentc): Ideally we'd like to avoid doing db operation in this function
        # It should be a pure function
        for edit in suggestion.package_edits.filter(
            edit_type=PackageEdit.EditType.REMOVE
        )
    )
    active_packages = {
        attr: pdata
        for attr, pdata in all_packages.items()
        if attr not in ignored_package_attrs
    }
    ignored_packages = {
        attr: pdata
        for attr, pdata in all_packages.items()
        if attr in ignored_package_attrs
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
