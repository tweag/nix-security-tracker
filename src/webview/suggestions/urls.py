from django.urls import path

from .views import SuggestionDetailView

app_name = "suggestion"

urlpatterns = [
    # Individual suggestion detail page
    path("<int:suggestion_id>/", SuggestionDetailView.as_view(), name="detail"),
]
