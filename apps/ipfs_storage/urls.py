"""apps/ipfs_storage/urls.py — IPFS endpoint routing."""

from django.urls import path

from apps.ipfs_storage.views import IPFSHealthView, IPFSUploadView

urlpatterns = [
    path("upload/", IPFSUploadView.as_view(), name="ipfs_upload"),
    path("health/", IPFSHealthView.as_view(), name="ipfs_health"),
]
