from rest_framework import status
from rest_framework.test import APITestCase
from django.urls import reverse
from authapp.models import *
from rest_framework import status


class LogoutTestCase(APITestCase):
    def setUp(self):

        self.logout_url = reverse("logout")
        # Create a user and authenticate to get JWT token
        self.user = User.objects.create_user(
            email="2019kumarsatish2019@gmail.com", password="password123"
        )
        response = self.client.post(
            reverse("login"),
            {"email": "2019kumarsatish2019@gmail.com", "password": "password123"},
        )
        self.token = response.data["access"]

    def test_logout_valid_token(self):
        # Send a POST request to logout
        self.client.credentials(HTTP_AUTHORIZATION="Bearer " + self.token)
        response = self.client.post("/auth/logout/")

        # Check if the response is successful
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["message"], "Successfully logged out.")
        print(f"\n{response.data}\n")

    def test_logout_without_credential(self):

        response = self.client.post(self.logout_url)

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(
            response.data["detail"], "Authentication credentials were not provided."
        )
        print(f"logout without credentials: {response.data}\n")
