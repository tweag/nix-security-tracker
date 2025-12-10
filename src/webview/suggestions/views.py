from typing import Any

from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import Http404
from django.shortcuts import get_object_or_404
from django.views.generic import TemplateView

from shared.logs.batches import batch_events
from shared.logs.events import remove_canceling_events
from shared.logs.fetchers import fetch_suggestion_events
from shared.models.cached import CachedSuggestions
from shared.models.linkage import CVEDerivationClusterProposal


class SuggestionBaseView(LoginRequiredMixin, TemplateView):
    """Base view for all suggestion-related views with common functionality."""

    def get_suggestion_context(
        self, suggestion_id_input: str | int | None
    ) -> dict[str, Any]:
        """Get common context data for a suggestion."""
        # Validate provided suggestion id
        if suggestion_id_input is None:
            raise Http404("Suggestion ID is required")
        try:
            suggestion_id_int = int(suggestion_id_input)
        except (ValueError, TypeError):
            raise Http404("Invalid suggestion ID")

        suggestion = get_object_or_404(
            CVEDerivationClusterProposal, id=suggestion_id_int
        )
        cached_suggestion = get_object_or_404(
            CachedSuggestions, proposal_id=suggestion_id_int
        )

        # Get activity log
        raw_events = fetch_suggestion_events(suggestion.pk)
        activity_log = batch_events(remove_canceling_events(raw_events, sort=True))

        return {
            "suggestion": suggestion,
            "cached_suggestion": cached_suggestion.payload,
            "activity_log": activity_log,
        }


class SuggestionDetailView(SuggestionBaseView):
    """Individual suggestion detail page."""

    template_name = "suggestions/suggestion_detail.html"

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        context = super().get_context_data(**kwargs)
        suggestion_id = kwargs.get("suggestion_id")  # Could be None if missing

        # Add suggestion context (with proper error handling)
        context.update(self.get_suggestion_context(suggestion_id))

        # Add status for template logic
        context["status_filter"] = context["suggestion"].status

        # FIXME: This should eventually be removed
        # Add page_obj context that the suggestion template expects
        # For detail views, we don't have pagination, so we create a mock object
        class MockPageObj:
            number = 1

        context["page_obj"] = MockPageObj()

        return context
