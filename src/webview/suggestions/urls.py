from django.urls import path

from .views.detail import SuggestionDetailView
from .views.lists import (
    AcceptedSuggestionsView,
    PublishedSuggestionsView,
    RejectedSuggestionsView,
    UntriagedSuggestionsView,
)
from .views.maintainers import (
    AddMaintainerView,
    DeleteMaintainerView,
    IgnoreMaintainerView,
    RestoreMaintainerView,
)
from .views.packages import IgnorePackageView, RestorePackageView
from .views.status import UpdateSuggestionStatusView

app_name = "suggestion"

urlpatterns = [
    # Individual suggestion detail page
    path("<int:suggestion_id>/", SuggestionDetailView.as_view(), name="detail"),
    # Lists
    path(
        "list/untriaged/",
        UntriagedSuggestionsView.as_view(),
        name="untriaged_suggestions",
    ),
    path("list/drafts/", AcceptedSuggestionsView.as_view(), name="draft_suggestions"),
    path(
        "list/dismissed/",
        RejectedSuggestionsView.as_view(),
        name="dismissed_suggestions",
    ),
    path(
        "list/published/",
        PublishedSuggestionsView.as_view(),
        name="published_suggestions",
    ),
    # Status change operation
    path(
        "<int:suggestion_id>/status",
        UpdateSuggestionStatusView.as_view(),
        name="update_status",
    ),
    # Package operations
    path(
        "<int:suggestion_id>/packages/<str:package_attr>/ignore/",
        IgnorePackageView.as_view(),
        name="ignore_package",
    ),
    path(
        "<int:suggestion_id>/packages/<str:package_attr>/restore/",
        RestorePackageView.as_view(),
        name="restore_package",
    ),
    # Maintainers operations
    path(
        "<int:suggestion_id>/maintainers/<int:github_id>/ignore/",
        IgnoreMaintainerView.as_view(),
        name="ignore_maintainer",
    ),
    path(
        "<int:suggestion_id>/maintainers/<int:github_id>/delete/",
        DeleteMaintainerView.as_view(),
        name="delete_maintainer",
    ),
    path(
        "<int:suggestion_id>/maintainers/<int:github_id>/restore/",
        RestoreMaintainerView.as_view(),
        name="restore_maintainer",
    ),
    path(
        "<int:suggestion_id>/maintainers/add/",
        AddMaintainerView.as_view(),
        name="add_maintainer",
    ),
]
