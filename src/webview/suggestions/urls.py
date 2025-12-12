from django.urls import path

from .views import SuggestionDetailView, UpdateSuggestionStatusView

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
]
