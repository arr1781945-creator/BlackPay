"""apps/zk_layer/urls.py — ZK proof endpoint routing."""

from django.urls import path

from apps.zk_layer.views import (
    GenerateBalanceProofView,
    GenerateIdentityProofView,
    VerifyBalanceProofView,
    VerifyIdentityProofView,
)

urlpatterns = [
    path("balance-proof/",         GenerateBalanceProofView.as_view(),  name="zk_balance_proof"),
    path("balance-proof/verify/",  VerifyBalanceProofView.as_view(),    name="zk_balance_verify"),
    path("identity-proof/",        GenerateIdentityProofView.as_view(), name="zk_identity_proof"),
    path("identity-proof/verify/", VerifyIdentityProofView.as_view(),   name="zk_identity_verify"),
]
