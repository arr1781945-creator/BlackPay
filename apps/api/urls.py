"""apps/api/urls.py — Unified API meta-endpoints."""

from django.urls import path

from apps.api.views import HealthView, PQCAlgorithmsView, VersionView

urlpatterns = [
    path("health/",          HealthView.as_view(),         name="health"),
    path("version/",         VersionView.as_view(),        name="version"),
    path("pqc/algorithms/",  PQCAlgorithmsView.as_view(),  name="pqc_algorithms"),
]
