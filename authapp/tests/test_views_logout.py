from rest_framework.test import APITestCase
from rest_framework import status
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken

from authapp.models import UserToken  # Ensure this model exists
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
import time
from datetime import timedelta

User = get_user_model()

class LogoutTest(APITestCase):
    def setUp(self):
        """Set up a user dynamically and generate access & refresh tokens."""
        self.user = User.objects.create_user(
            email="testuser@example.com",
            password="Test@#123"
        )
        self.user.is_email_verified = True
        self.user.is_mobile_verified = True
        self.user.save()

        self.logout_url = "/auth/logout/"

        # Generate JWT tokens
        self.refresh = RefreshToken.for_user(self.user)
        self.access = str(self.refresh.access_token)

        # Store tokens in UserToken model
        self.user_token = UserToken.objects.create(
            access_token=self.access,
            refresh_token=str(self.refresh)
        )

        self.headers = {"HTTP_AUTHORIZATION": f"Bearer {self.access}"}
    
    def test_authentication_for_invalid_token(self):
        """ Test case for authentication for invalid token."""
        response = self.client.post(self.logout_url, {}, headers={"HTTP_AUTHORIZATION": f"Bearer invalidtoken"})
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn('detail',response.data)

    def test_authentication_for_token_not_provided(self):
        """Test case for missing token."""
        response = self.client.post(self.logout_url, {})
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data.get("detail"), "Authentication credentials were not provided.")

    def test_with_valid_token(self):
        """ Test case success for valid token. """

        print(self.headers)
        response = self.client.post(self.logout_url, {}, **self.headers)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data.get("message"), "Successfully logged out.")

    def test_expired_token(self):
        """Test case for logout with an expired access token."""

        # Create an expired access token (set expiration time to past)
        expired_access = AccessToken.for_user(self.user)
        from datetime import datetime
        expired_access.set_exp(from_time=datetime.now() - timedelta(minutes=10))  # Expired 10 minutes ago
        expired_token_str = str(expired_access)

        # Send logout request with expired token
        response = self.client.post(
            self.logout_url,
            {},
            **{"HTTP_AUTHORIZATION": f"Bearer {expired_token_str}"}
        )

        # Expected response for an expired token
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data.get("message"), "token_not_valid")