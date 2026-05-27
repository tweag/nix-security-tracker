from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpRequest, HttpResponse, HttpResponseForbidden
from django.shortcuts import redirect
from django.urls import reverse
from django.views import View

from shared.auth import user_can_edit_suggestion
from shared.models.linkage import CVEDerivationClusterProposal


class ResetIssueDraftView(LoginRequiredMixin, View):
    """Remove all suggestions from the issue draft."""

    http_method_names = ["post"]

    def post(self, request: HttpRequest) -> HttpResponse:
        if not user_can_edit_suggestion(request.user):
            return HttpResponseForbidden()

        CVEDerivationClusterProposal.objects.filter(in_issue_draft=True).update(
            in_issue_draft=False
        )

        return redirect(reverse("webview:suggestion:issue_draft"))
