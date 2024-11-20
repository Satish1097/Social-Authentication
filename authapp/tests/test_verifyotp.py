from django.test import TestCase
from rest_framework import status
import unittest
from django.core.mail import send_mail
from rest_framework.test import APIClient
from django.urls import reverse
from authapp.models import *
import pyotp
from rest_framework import status


class VerifyOTPAPIViewTests(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.url = reverse("verifyotp")  # Replace with your actual URL path

    def test_verify_otp_success_with_mobile(self):
        # Generate a random secret key for TOTP
        secret_key = pyotp.random_base32()
        # Create an OTP instance using the secret key
        totp = pyotp.TOTP(secret_key, interval=120)
        otp_code = totp.now()  # Generate OTP code
        # time.sleep(240)

        otp_record = OTP.objects.create(
            mobile="7762019670", secret_key=secret_key, is_used=False
        )
        response = self.client.post(
            self.url,
            {
                "mobile": "7762019670",
                "otp": otp_code,
            },
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["message"], "OTP verified successfully.")
        print(f"Response for verifyotp with mobile: {response.data}\n")

    def test_verify_otp_with_false_otp_with_mobile(self):
        response = self.client.post(
            self.url,
            {
                "mobile": "7762019670",
                "otp": 123456,
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response.data["error"], "OTP not found or already used.")
        print(f"Response for false OTP and false mobile {response.data}\n")

    def test_verify_otp_with_invalid_otp_with_mobile(self):
        # Generate a random secret key for TOTP
        secret_key = pyotp.random_base32()
        # Create an OTP instance using the secret key
        totp = pyotp.TOTP(secret_key, interval=120)
        otp_code = totp.now()  # Generate OTP code
        # time.sleep(240)

        otp_record = OTP.objects.create(
            mobile="7762019670", secret_key=secret_key, is_used=False
        )

        response = self.client.post(
            self.url,
            {
                "mobile": "7762019670",
                "otp": 123456,
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["error"], "Invalid OTP.")
        print(f"Response for false OTP with mobile {response.data}\n")

    def test_verify_otp_success_with_email(self):
        # Generate a random secret key for TOTP
        secret_key = pyotp.random_base32()
        # Create an OTP instance using the secret key
        totp = pyotp.TOTP(secret_key, interval=120)
        otp_code = totp.now()  # Generate OTP code
        # time.sleep(240)

        otp_record = OTP.objects.create(
            email="2019kumarsatish2019@gmail.com", secret_key=secret_key, is_used=False
        )
        response = self.client.post(
            self.url,
            {
                "email": "2019kumarsatish2019@gmail.com",
                "otp": otp_code,
            },
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["message"], "OTP verified successfully.")
        print(f"\nResponse for verifyotp wit email: {response.data}\n")

    def test_verify_otp_with_false_otp_with_email(self):
        response = self.client.post(
            self.url,
            {
                "email": "2019kumarsatish2019@gmail.com",
                "otp": 123456,
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response.data["error"], "OTP not found or already used.")
        print(f"Response for false OTP and false email {response.data}\n")

    def test_verify_false_otp_with_email(self):
        # Generate a random secret key for TOTP
        secret_key = pyotp.random_base32()
        # Create an OTP instance using the secret key
        totp = pyotp.TOTP(secret_key, interval=120)
        otp_code = totp.now()  # Generate OTP code
        # time.sleep(240)

        otp_record = OTP.objects.create(
            email="2019kumarsatish2019@gmail.com", secret_key=secret_key, is_used=False
        )

        response = self.client.post(
            self.url,
            {
                "email": "2019kumarsatish2019@gmail.com",
                "otp": 123456,
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["error"], "Invalid OTP.")
        print(f"\nResponse for false OTP with email: {response.data}\n")
