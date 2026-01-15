from django.urls import path

from .views import (
    AcceptedSuggestionsView,
    IgnorePackageView,
    PublishedSuggestionsView,
    RejectedSuggestionsView,
    RestorePackageView,
    SuggestionDetailView,
    UntriagedSuggestionsView,
    UpdateSuggestionStatusView,
)

app_name = "suggestion"

urlpatterns = [
    # Individual suggestion detail page
    path("<int:suggestion_id>/", SuggestionDetailView.as_view(), name="detail"),
    # Status change endpoint
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
]
