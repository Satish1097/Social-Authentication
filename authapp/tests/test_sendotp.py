from unittest.mock import patch, MagicMock
from django.core.mail import send_mail
from django.test import TestCase
from rest_framework import status
from rest_framework.test import APIClient
from django.urls import reverse
from authapp.models import *
from rest_framework import status


class VerifyAPIViewTests(TestCase):

    def setUp(self):
        # Set up the test client
        self.client = APIClient()
        self.url = reverse(
            "sendotp"
        )  # Use reverse() to get the correct URL for your view

    def test_send_otp_to_email(self):
        # Case when email already exists in the system
        email = "test@example.com"
        User.objects.create(email=email, mobile="9876543210", password="password")

        # Call the API with the existing email
        response = self.client.post(
            self.url,  # Using reversed URL for the endpoint
            {"email": email},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["message"], "Email already exists")
        print(f"Response for sendotp email already exists: {response.data}\n")

    def test_send_otp_to_mobile(self):
        # Case when mobile already exists in the system
        mobile = "9876543211"
        User.objects.create(
            email="test@example1.com", mobile=mobile, password="password"
        )

        # Call the API with the existing mobile number
        response = self.client.post(
            self.url,
            {"mobile": mobile},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["message"], "Mobile number already exists")

        print(f"Response for sendotp with mobile exists: {response.data}\n")

    def test_missing_email_and_mobile(self):
        # Case when neither email nor mobile is provided
        response = self.client.post(
            self.url,
            {},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response.data["message"], "Please provide either email or mobile number"
        )
        print(f"\nResponse for sendotp with No data: {response.data}\n")

    def test_send_otp_new_email(self):
        email = "2019kumarsatish2019@gmail.com"
        # Call the API with the new email
        response = self.client.post(
            self.url,
            {"email": email},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["message"], "OTP sent to your email")

        print(f"Response for sendotp on new email: {response.data}\n")

    # def test_send_otp_new_mobile(self):

    #     mobile = "7762019670"

    #     response = self.client.post(
    #         self.url,  # Ensure this matches your actual URL
    #         {"mobile": mobile},
    #         format="json",
    #     )
    #     self.assertEqual(response.status_code, status.HTTP_200_OK)
    #     self.assertEqual(
    #         response.data["message"], "OTP sent successfully to your mobile"
    #     )
    #     print(f"Response for sendotp new mobile: {response.data}\n")
