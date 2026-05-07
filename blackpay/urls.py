from django.contrib import admin
from django.urls import include, path
from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/v1/auth/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("api/v1/auth/token/verify/",  TokenVerifyView.as_view(),  name="token_verify"),
    path("api/v1/auth/",       include("apps.users.urls")),
    path("api/v1/payments/",   include("apps.payments.urls")),
    path("api/v1/wallet/",     include("apps.wallet.urls")),
    path("api/v1/compliance/", include("apps.compliance.urls")),
    path("api/v1/zk/",         include("apps.zk_layer.urls")),
    path("api/v1/ipfs/",       include("apps.ipfs_storage.urls")),
    path("api/v1/",            include("apps.api.urls")),
]
