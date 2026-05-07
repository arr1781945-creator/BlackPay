"""apps/wallet/urls.py — Wallet endpoint routing."""

from django.urls import path

from apps.wallet.views import (
    BalanceListView,
    ExchangeRateListView,
    InternalTransferView,
    WalletView,
)

urlpatterns = [
    path("",          WalletView.as_view(),          name="wallet"),
    path("balances/", BalanceListView.as_view(),      name="balance_list"),
    path("transfer/", InternalTransferView.as_view(), name="internal_transfer"),
    path("rates/",    ExchangeRateListView.as_view(), name="exchange_rates"),
]
