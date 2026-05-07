"""apps/users/urls.py — User and auth endpoint routing."""

from django.urls import path

from apps.users.views import (
    FIDO2AuthBeginView,
    FIDO2AuthCompleteView,
    FIDO2CredentialDeleteView,
    FIDO2CredentialListView,
    FIDO2RegisterBeginView,
    FIDO2RegisterCompleteView,
    LoginView,
    PQCKeyGenerateView,
    PQCKeyListView,
    PQCMFAChallengeView,
    PQCMFAVerifyView,
    PasswordChangeView,
    ProfileView,
    RegisterView,
)

urlpatterns = [
    # Registration / login
    path("register/",          RegisterView.as_view(),       name="register"),
    path("login/",             LoginView.as_view(),          name="login"),
    path("profile/",           ProfileView.as_view(),        name="profile"),
    path("password/change/",   PasswordChangeView.as_view(), name="password_change"),

    # PQC MFA
    path("mfa/pqc/challenge/", PQCMFAChallengeView.as_view(), name="pqc_mfa_challenge"),
    path("mfa/pqc/verify/",    PQCMFAVerifyView.as_view(),    name="pqc_mfa_verify"),

    # FIDO2 registration
    path("fido2/register/begin/",    FIDO2RegisterBeginView.as_view(),    name="fido2_reg_begin"),
    path("fido2/register/complete/", FIDO2RegisterCompleteView.as_view(), name="fido2_reg_complete"),

    # FIDO2 authentication
    path("fido2/auth/begin/",    FIDO2AuthBeginView.as_view(),    name="fido2_auth_begin"),
    path("fido2/auth/complete/", FIDO2AuthCompleteView.as_view(), name="fido2_auth_complete"),

    # FIDO2 credential management
    path("fido2/credentials/",          FIDO2CredentialListView.as_view(),   name="fido2_cred_list"),
    path("fido2/credentials/<uuid:pk>/", FIDO2CredentialDeleteView.as_view(), name="fido2_cred_delete"),

    # PQC key management
    path("keys/",          PQCKeyListView.as_view(),     name="pqc_key_list"),
    path("keys/generate/", PQCKeyGenerateView.as_view(), name="pqc_key_generate"),
]
