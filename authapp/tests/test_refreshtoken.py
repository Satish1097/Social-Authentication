from rest_framework import status
from django.urls import reverse
from authapp.models import *
from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import RefreshToken


class RefreshTokenTestCase(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="2019kumarsatish2019@gmail.com", password="password123"
        )
        self.refresh_token = RefreshToken.for_user(self.user)
        self.access_token = str(self.refresh_token.access_token)
        self.user_token = UserToken.objects.create(
            access_token=self.access_token, refresh_token=self.refresh_token
        )
        self.refresh_url = reverse("refresh")

    def test_refreshtoken_valid_token(self):
        # Send a POST request to refresh token
        response = self.client.post(
            self.refresh_url,
            {"refresh": str(self.refresh_token)},  # Send the refresh token in the body
            HTTP_AUTHORIZATION=f"Bearer {self.access_token}",  # Include the access token in the Authorization header
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        print(f"Response of RefreshToken {response.data}\n\n")

    def test_refreshtoken_with_invalid_token(self):
        invalid_refresh = str(self.refresh_token) + "x"
        response = self.client.post(
            self.refresh_url,
            {"refresh": invalid_refresh},
            HTTP_AUTHORIZATION=f"Bearer {self.access_token}",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["error"], "Token is invalid or expired")
        print(f"Response of RefreshToken {response.data}\n\n")
