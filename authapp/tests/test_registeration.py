from rest_framework.test import APITestCase
from rest_framework import status
from authapp.models import User, OTP
from django.urls import reverse


class RegistrationAPIViewTests(APITestCase):
    def setUp(self):
        self.url = reverse("register")
        self.valid_data = {
            "email": "testuser@example.com",
            "password": "strongpassword123",
            "password2": "strongpassword123",
            "username": "testuser",
            "mobile": "1234567890",
        }

        # Create OTP for email or mobile to simulate a validated user
        self.valid_otp_email = OTP.objects.create(
            email="testuser@example.com", mobile="", secret_key="secret", is_used=True
        )
        self.valid_otp_mobile = OTP.objects.create(
            email="", mobile="1234567890", secret_key="secret", is_used=True
        )

    def test_registration_success_with_valid_email_otp(self):
        # Use valid OTP for email and mobile
        response = self.client.post(self.url, self.valid_data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        print(f"\nResponse for Register Success: {response.data}")

    def test_registration_fail_without_valid_otp(self):
        self.valid_otp_email.is_used = False
        self.valid_otp_mobile.is_used = False
        self.valid_otp_email.save()
        self.valid_otp_mobile.save()

        response = self.client.post(self.url, self.valid_data)

        if response.status_code != status.HTTP_400_BAD_REQUEST:
            print(f"\nResponse={response.data}\nn")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            response.data["message"], "Email or phone number not validated."
        )
        print(f"Response for unverified email or password: {response.data}\n")

    def test_registration_fail_if_passwords_do_not_match(self):
        self.valid_data["password2"] = "differentpassword123"
        response = self.client.post(self.url, self.valid_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        print(f"\nResponse for not matched password:  {response.data}\n")
