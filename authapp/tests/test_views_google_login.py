from rest_framework.test import APITestCase
from rest_framework import status
from unittest.mock import patch
import requests
from django.urls import reverse


class GoogleAuthAPIViewTests(APITestCase):
    def setUp(self):
        self.url = reverse("google_auth")
        self.valid_token = "valid_google_oauth_token"
        self.invalid_token = "invalid_google_oauth_token"
        self.user_email = "testuser@example.com"

    @patch("requests.get")
    def test_google_auth_success(self, mock_get):
        # Simulate a successful response from Google
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {"email": self.user_email}

        response = self.client.post(self.url, {"token": self.valid_token})
        print("*"*50)
        print(response.data)
        print("*"*50)

        self.assertIn('access',response.data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)

    @patch("requests.get")
    def test_google_auth_invalid_token(self, mock_get):
        # Simulate a failure response from Google (e.g., invalid token)
        mock_get.return_value.status_code = 400
        mock_get.return_value.json.return_value = {"error": "Invalid token"}

        response = self.client.post(self.url, {"token": self.invalid_token})

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["error"], "Invalid token")

    def test_google_auth_missing_token(self):
        # Test when no token is provided
        response = self.client.post(self.url, {})

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["error"], "Token is required")

    @patch("requests.get")
    def test_google_auth_token_missing_email(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {}

        response = self.client.post(self.url, {"token": self.valid_token})

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["error"], "Email not found")


    @patch("requests.get")
    def test_google_auth_token_verification_failure(self, mock_get):
        mock_get.side_effect = requests.RequestException("Network error")
        response = self.client.post(self.url, {"token": self.valid_token})

        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertEqual(response.data["error"], "Failed to verify token with Google")

