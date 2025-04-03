from rest_framework import status
from rest_framework.test import APITestCase
from authapp.models import User
from django.core import mail
from unittest.mock import patch

class ForgotPasswordTest(APITestCase):
    def setUp(self):
        """Set up test user."""
        self.user = User.objects.create(mobile="9172048485", email="nitinshenigaram7860@gmail.com")
        self.forgot_password_url = "/auth/password-reset/"
        return super().setUp()

    def test_missing_mobile_and_email(self):
        """Test error response when both mobile and email are missing."""
        response = self.client.post(self.forgot_password_url, {}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["message"], "Enter either mobile or email")

    def test_user_does_not_exist_by_email(self):
        """Test error response when email does not exist in the system."""
        payload = {"email": "nonexistent@example.com"}  
        response = self.client.post(self.forgot_password_url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["message"], "User does not exist with this email")

    def test_user_does_not_exist_by_mobile(self):
        """Test error response when mobile does not exist in the system."""
        payload = {"mobile": "9999999999"}  
        response = self.client.post(self.forgot_password_url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["message"], "User does not exist with this mobile")


    def test_password_reset_success_email(self):
        """Test successful password reset when user exists (email case)."""
        
        payload = {"email": self.user.email}
        print("*"*20)
        print(self.user.email)
        print("*"*20)

        response = self.client.post(self.forgot_password_url, payload, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["message"], "Password reset link sent on email!")
        



    def test_password_reset_success_mobile(self):
        """Test successful password reset when user exists (mobile case)."""
       
        payload = {"mobile": self.user.mobile}
        response = self.client.post(self.forgot_password_url, payload, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["message"], "reset link sent on mobile!")

