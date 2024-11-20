from django.test import TestCase
from unittest.mock import patch
from rest_framework import status
from rest_framework.test import APIClient
from authapp.models import OTP  # Adjust based on your project structure
import pyotp
from django.urls import reverse


class VerifyOTPAPIViewTests(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.url = reverse("verifyotp")  # Replace with your actual URL path

    def test_verify_otp_success(self):
        # Setup a mock OTP record
        secret_key = pyotp.random_base32()
        totp = pyotp.TOTP(secret_key)
        otp_code = totp.now()

        otp_record = OTP.objects.create(
            mobile="9123456789", secret_key=secret_key, is_used=False
        )

        # Attempt to verify the OTP
        response = self.client.post(
            self.url,
            {"mobile": "9123456789", "otp": otp_code},
            format="json",
        )

        # Assert success response
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["message"], "OTP verified successfully.")
        otp_record.refresh_from_db()  # Refresh from DB to check values
        self.assertTrue(otp_record.is_used)
        self.assertTrue(otp_record.is_verified)

    def test_verify_otp_success_with_email(self):
        # Setup a mock OTP record with email
        secret_key = pyotp.random_base32()
        totp = pyotp.TOTP(secret_key)
        otp_code = totp.now()

        otp_record = OTP.objects.create(
            email="user@example.com", secret_key=secret_key, is_used=False
        )

        # Attempt to verify the OTP using email
        response = self.client.post(
            self.url,
            {"email": "user@example.com", "otp": otp_code},
            format="json",
        )

        # Assert success response
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["message"], "OTP verified successfully.")
        otp_record.refresh_from_db()  # Refresh from DB to check values
        self.assertTrue(otp_record.is_used)
        self.assertTrue(otp_record.is_verified)

    def test_verify_otp_without_mobile_or_email(self):
        # Attempt to verify without providing mobile or email
        response = self.client.post(
            self.url,
            {"otp": "123456"},
            format="json",
        )

        # Assert error response
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["error"], "Either mobile or email is required.")

    def test_verify_otp_without_otp(self):
        # Attempt to verify without providing an OTP
        response = self.client.post(
            self.url,
            {"mobile": "9123456789"},
            format="json",
        )

        # Assert error response
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["error"], "OTP is required.")

    def test_verify_otp_with_invalid_code(self):
        # Setup a mock OTP record
        secret_key = pyotp.random_base32()

        otp_record = OTP.objects.create(
            mobile="9123456789",
            secret_key=secret_key,
            is_used=False,
        )

        # Attempt to verify with an invalid OTP
        response = self.client.post(
            self.url,
            {"mobile": "9123456789", "otp": "wrong-otp"},
            format="json",
        )

        # Assert error response
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["error"], "Invalid OTP.")

    def test_verify_otp_with_used_otp(self):
        # Setup a mock OTP record
        secret_key = pyotp.random_base32()
        otp_code = pyotp.TOTP(secret_key).now()

        otp_record = OTP.objects.create(
            mobile="9123456789",
            secret_key=secret_key,
            is_used=True,
        )

        # Attempt to verify a used OTP
        response = self.client.post(
            self.url,
            {"mobile": "9123456789", "otp": otp_code},
            format="json",
        )

        # Assert error response
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["error"], "OTP not found or already used.")

    # def test_verify_otp_not_found(self):
    #     # Attempt to verify OTP for
