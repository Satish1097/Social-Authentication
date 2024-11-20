from django.urls import path
from authapp.views import *

# from rest_framework_simplejwt.views import (
#     TokenObtainSlidingView,
#     TokenRefreshView,
# )

urlpatterns = [
    path("sendotp/", VerifyAPIView.as_view(), name="sendotp"),
    path("verifyotp/", VerifyOTPAPIView.as_view(), name="verifyotp"),
    path("register/", RegisterationAPIView.as_view(), name="register"),
    path("login/", CustomTokenObtainPairView.as_view(), name="login"),
    # path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("token/refresh/", CustomTokenRefreshView.as_view(), name="refresh"),
    path("logout/", LogoutAPIView.as_view(), name="logout"),
    path(
        "password-reset/",
        PasswordForgotRequestView.as_view(),
        name="password_forgot_request",
    ),
    path(
        "password-reset-confirm/<uidb64>/<token>/",
        PasswordConfirmView.as_view(),
        name="password_confirm",
    ),
    path("reset_password/", ResetPasswordAPIView.as_view(), name="reset_password"),
    path(
        "google/", GoogleAuthAPIView.as_view(), name="google_auth"
    ),  # Your API endpoint
    path(
        "google-auth-test/", google_auth_test, name="google_auth_test"
    ),  # Serve the HTML template
]
