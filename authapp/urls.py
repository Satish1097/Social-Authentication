from django.urls import path
from authapp.views import *

urlpatterns = [
    path("sendotp/", VerifyAPIView.as_view(), name="sendotp"),
    path("verifyotp/", VerifyOTPAPIView.as_view(), name="verifyotp/"),
    path("register/", RegisterationAPIView.as_view(), name="register"),
    path(
        "google/", GoogleAuthAPIView.as_view(), name="google_auth"
    ),  # Your API endpoint
    path(
        "google-auth-test/", google_auth_test, name="google_auth_test"
    ),  # Serve the HTML template
]
