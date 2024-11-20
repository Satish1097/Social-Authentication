from django.test import TestCase
from django.urls import reverse
from unittest.mock import patch, MagicMock
from rest_framework import status
from django.core.mail import send_mail
from twilio.rest import Client
from authapp.models import *
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode


class PasswordResetTests(TestCase):

    def setUp(self):
        # Create a test user
        self.user = User.objects.create_user(
            username="testuser",
            email="2019kumarsatish2019@gmail.com",
            password="password123",
        )
        self.user.mobile = "7762019670"
        self.user.save()

        self.forgot_password_url = reverse("password_forgot_request")

        self.token = default_token_generator.make_token(self.user)
        self.uidb64 = urlsafe_base64_encode(force_bytes(self.user.pk))
        self.password_reset_url = reverse(
            "password_confirm",
            kwargs={"uidb64": self.uidb64, "token": self.token},
        )

    def test_forgot_password_success_email(self):
        response = self.client.post(
            self.forgot_password_url, {"email": "2019kumarsatish2019@gmail.com"}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["message"], "Password reset link sent on email!")
        print(f"Response forgot pass with email:{ response.data}\n")

    def test_forgot_password_email_not_exist(self):
        response = self.client.post(
            self.forgot_password_url, {"email": "2019kumarsatish@gmail.com"}
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response.data["message"], "User does not exist with this email"
        )
        print(f"Response forgot pass with email not exists:{ response.data}\n")

    # def test_forgot_password_success_mobile(self):
    #     response = self.client.post(self.forgot_password_url, {"mobile": "7762019670"})

    #     if response.status_code != status.HTTP_200_OK:
    #         print(response.data, response.status_code)
    #     self.assertEqual(response.status_code, status.HTTP_200_OK)
    #     self.assertEqual(response.data["message"], "reset link sent on mobile!")
    #     print(f"Response forgot pass with mobile:{ response.data}\n")

    def test_forgot_password_with_mobile_not_exist(self):
        response = self.client.post(self.forgot_password_url, {"mobile": "7782019670"})

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response.data["message"], "User does not exist with this mobile"
        )
        print(f"Response forgot pass with mobile not exists:{ response.data}\n")

    def test_forgot_password_with_mobile_email_does_not_exists(self):
        response = self.client.post(self.forgot_password_url, {})

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["message"], "Enter either mobile or email")
        print(
            f"Response forgot pass with mobile and email not exist:{ response.data}\n"
        )

    def test_password_confirm_success(self):
        # Generate the reset token and UID (this should be valid)
        token = default_token_generator.make_token(self.user)
        uid = urlsafe_base64_encode(force_bytes(self.user.pk))
        reset_link = f"http://127.0.0.1:8000/auth/password-reset-confirm/{uid}/{token}/"

        response = self.client.post(
            self.password_reset_url, {"password": "newpassword123"}
        )

        if response.status_code != status.HTTP_200_OK:
            print(f"\n\n{response.data}\n\n")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["message"], "Password has been reset.")

        print(f"Response for password confirm: {response.data}")
