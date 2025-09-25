"""
Configuration constants for webview classes.

This module contains constants extracted from view classes to improve
maintainability and reduce magic numbers throughout the codebase.
"""

from shared.models.linkage import CVEDerivationClusterProposal


class ViewConfig:
    """Configuration constants for webview classes."""

    # Pagination settings
    DEFAULT_PAGINATE_BY = 10
    PAGES_ON_EACH_SIDE = 2
    PAGES_ON_ENDS = 1

    # Search settings
    SEARCH_NORMALIZATION_VALUE = 1


class SuggestionRoutes:
    """URL routes for different suggestion statuses."""

    STATUS_ROUTES = {
        CVEDerivationClusterProposal.Status.PENDING.value: "/suggestions",
        CVEDerivationClusterProposal.Status.ACCEPTED.value: "/drafts",
        CVEDerivationClusterProposal.Status.REJECTED.value: "/dismissed",
        CVEDerivationClusterProposal.Status.PUBLISHED.value: "/issues",
    }


class ResponseMessages:
    """Standard response messages."""

    MISSING_GITHUB_HANDLE = "Missing GitHub handle for new maintainer"
    ALREADY_MAINTAINER = "Already a maintainer"
    FETCH_MAINTAINER_ERROR = "Could not fetch maintainer from GitHub"
    ALREADY_EXTRA_MAINTAINER = "Already added as an extra maintainer"
    UNEXPECTED_MAINTAINER_EDIT = "Unexpected maintainer edit status"
    MISSING_EDIT_MAINTAINER_ID = (
        "Missing edit_maintainer_id in request for maintainer edition"
    )


class HttpStatusCodes:
    """HTTP status codes used in views."""

    UNPROCESSABLE_ENTITY = 422
