from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView



class IssueDraftView(LoginRequiredMixin, TemplateView):
    template_name = "issue_draft/page.html"

