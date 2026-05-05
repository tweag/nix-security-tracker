from django.urls import include, path
from rest_framework import routers

from api.views import NixpkgsIssueViewSet, SuggestionViewSet

v1_router = routers.DefaultRouter(trailing_slash=False)
v1_router.register(r"issues", NixpkgsIssueViewSet)
v1_router.register("suggestions", SuggestionViewSet)

urlpatterns = [
    path("v1/", include(v1_router.urls)),
]
