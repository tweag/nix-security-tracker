from django.urls import path

from .views import (
    AcceptedSuggestionsView,
    PublishedSuggestionsView,
    RejectedSuggestionsView,
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
    path(
        "untriaged/", UntriagedSuggestionsView.as_view(), name="untriaged_suggestions"
    ),
    path("drafts/", AcceptedSuggestionsView.as_view(), name="draft_suggestions"),
    path("dismissed/", RejectedSuggestionsView.as_view(), name="dismissed_suggestions"),
    path(
        "published/", PublishedSuggestionsView.as_view(), name="published_suggestions"
    ),
]
