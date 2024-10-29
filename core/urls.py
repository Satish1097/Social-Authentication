from rest_framework_simplejwt.views import (
    TokenObtainSlidingView,
    TokenRefreshSlidingView,
)
from authapp.views import profileview

from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path("admin/", admin.site.urls),
    path("auth/", include("authapp.urls")),
    path("accounts/", include("allauth.urls")),
    path("accounts/", include("allauth.socialaccount.urls")),
    path("accounts/profile/", profileview, name="profile"),
    path("auth/login/", TokenObtainSlidingView.as_view(), name="token_obtain"),
    path("api/token/refresh/", TokenRefreshSlidingView.as_view(), name="token_refresh"),
]
