from typing import Any

from django.http import Http404
from django.shortcuts import get_object_or_404

from shared.models.linkage import (
    CVEDerivationClusterProposal,
)

from .base import SuggestionBaseView, get_suggestion_context


class SuggestionDetailView(SuggestionBaseView):
    """Individual suggestion detail page."""

    template_name = "suggestions/suggestion_detail.html"

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        context = super().get_context_data(**kwargs)
        suggestion_id_input = kwargs.get("suggestion_id")  # Could be None if missing

        # Validate provided suggestion id
        if suggestion_id_input is None:
            raise Http404("Suggestion ID is required")
        try:
            suggestion_id = int(suggestion_id_input)
            suggestion = get_object_or_404(
                CVEDerivationClusterProposal, id=suggestion_id
            )
            context.update({"suggestion_context": get_suggestion_context(suggestion)})
            return context
        except (ValueError, TypeError):  # FIXME(@florentc): also catch db error
            raise Http404("Invalid suggestion ID")
