"""apps/compliance/urls.py — Compliance endpoint routing."""

from django.urls import path

from apps.compliance.views import (
    AuditTrailListView,
    ConsentView,
    GDPRDataExportView,
    GDPRRequestListCreateView,
    KYCStatusView,
    KYCSubmitView,
)

urlpatterns = [
    path("gdpr/request/", GDPRRequestListCreateView.as_view(), name="gdpr_request"),
    path("gdpr/export/",  GDPRDataExportView.as_view(),        name="gdpr_export"),
    path("consent/",      ConsentView.as_view(),                name="consent"),
    path("audit/",        AuditTrailListView.as_view(),         name="audit_trail"),
    path("kyc/",          KYCStatusView.as_view(),              name="kyc_status"),
    path("kyc/submit/",   KYCSubmitView.as_view(),              name="kyc_submit"),
]
