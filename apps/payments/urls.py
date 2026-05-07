"""apps/payments/urls.py — Payment endpoint routing."""

from django.urls import path

from apps.payments.views import (
    CreateCryptoPaymentView,
    CreateFiatPaymentView,
    NOWPaymentsWebhookView,
    StripeWebhookView,
    TransactionDetailView,
    TransactionListView,
    TransakWebhookView,
)

urlpatterns = [
    # Payment creation
    path("crypto/create/", CreateCryptoPaymentView.as_view(), name="create_crypto_payment"),
    path("fiat/create/",   CreateFiatPaymentView.as_view(),   name="create_fiat_payment"),

    # Transactions
    path("transactions/",          TransactionListView.as_view(),   name="transaction_list"),
    path("transactions/<uuid:pk>/", TransactionDetailView.as_view(), name="transaction_detail"),

    # Webhooks (public, signature-verified)
    path("webhooks/nowpayments/", NOWPaymentsWebhookView.as_view(), name="webhook_nowpayments"),
    path("webhooks/stripe/",      StripeWebhookView.as_view(),      name="webhook_stripe"),
    path("webhooks/transak/",     TransakWebhookView.as_view(),     name="webhook_transak"),
]
