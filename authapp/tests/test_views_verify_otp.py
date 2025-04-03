from rest_framework import status
from rest_framework.test import APITestCase
from django.contrib.auth import get_user_model
from authapp.models import OTP
import pyotp

User = get_user_model()

from rest_framework import status
from rest_framework.test import APITestCase
from authapp.models import OTP, User
import pyotp

class VerifyOtpTest(APITestCase):
    def setUp(self):
        """Set up test user and OTP records for both mobile and email."""
        self.user = User.objects.create(
            mobile="9172048485", email="test@example.com"
        )

        self.otp_secret_mobile = pyotp.random_base32()
        self.otp_mobile = OTP.objects.create(
            mobile=self.user.mobile,
            email="",
            secret_key=self.otp_secret_mobile,
            is_used=False,
        )

        self.otp_secret_email = pyotp.random_base32()
        self.otp_email = OTP.objects.create(
            mobile="",
            email=self.user.email,
            secret_key=self.otp_secret_email,
            is_used=False,
        )

        self.verify_otp_url = "/auth/verify-otp/"
        return super().setUp()

    def test_missing_mobile_and_email(self):
        """Test error response when both mobile and email are missing."""
        response = self.client.post(self.verify_otp_url, {}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["error"], "Either mobile or email is required.")

    def test_missing_otp(self):
        """Test error response when OTP is missing."""
        payload = {"mobile": self.user.mobile}
        response = self.client.post(self.verify_otp_url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["error"], "OTP is required.")

    def test_invalid_otp_mobile(self):
        """Test error response when an invalid OTP is provided for mobile."""
        payload = {"mobile": self.user.mobile, "otp": "999999"}
        response = self.client.post(self.verify_otp_url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["error"], "Invalid OTP.")

    def test_invalid_otp_email(self):
        """Test error response when an invalid OTP is provided for email."""
        payload = {"email": self.user.email, "otp": "999999"}
        response = self.client.post(self.verify_otp_url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["error"], "Invalid OTP.")

    def test_expired_or_used_otp_mobile(self):
        """Test error response when OTP is already used or expired for mobile."""
        self.otp_mobile.is_used = True
        self.otp_mobile.save()

        payload = {"mobile": self.user.mobile, "otp": "123456"}  
        response = self.client.post(self.verify_otp_url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response.data["error"], "OTP not found or already used.")

    def test_expired_or_used_otp_email(self):
        """Test error response when OTP is already used or expired for email."""
        self.otp_email.is_used = True
        self.otp_email.save()

        payload = {"email": self.user.email, "otp": "123456"}
        response = self.client.post(self.verify_otp_url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response.data["error"], "OTP not found or already used.")

    def test_successful_otp_verification_mobile(self):
        """ Test successful OTP verification for mobile. """
        totp = pyotp.TOTP(self.otp_mobile.secret_key, interval=120)
        valid_otp = totp.now()

        payload = {"mobile": self.user.mobile, "otp": valid_otp}
        response = self.client.post(self.verify_otp_url, payload, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["message"], "OTP verified successfully.")

        self.otp_mobile.refresh_from_db()
        self.assertTrue(self.otp_mobile.is_used)

        self.user.refresh_from_db()
        self.assertTrue(self.user.is_mobile_verified)

    def test_successful_otp_verification_email(self):
        """Test successful OTP verification for email."""
        totp = pyotp.TOTP(self.otp_email.secret_key, interval=120)
        valid_otp = totp.now()

        payload = {"email": self.user.email, "otp": valid_otp}
        response = self.client.post(self.verify_otp_url, payload, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["message"], "OTP verified successfully.")

        self.otp_email.refresh_from_db()
        self.assertTrue(self.otp_email.is_used)

        self.user.refresh_from_db()
        self.assertTrue(self.user.is_email_verified)