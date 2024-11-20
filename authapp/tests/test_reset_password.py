from rest_framework import status
from django.urls import reverse
from authapp.models import *
from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import RefreshToken


class ResetPasswordTestCase(APITestCase):

    def setUp(self):
        self.reset_url = reverse("reset_password")
        self.user = User.objects.create_user(
            email="2019kumarsatish2019@gmail.com", password="password123"
        )
        self.refresh_token = RefreshToken.for_user(self.user)
        self.access_token = str(self.refresh_token.access_token)
        self.user_token = UserToken.objects.create(
            access_token=self.access_token, refresh_token=self.refresh_token
        )

    def test_reset_password_with_valid_user(self):
        response = self.client.post(
            self.reset_url,
            {
                "email": "2019kumarsatish2019@gmail.com",
                "password": "password123",
                "new_password": "newpassword",
            },
            HTTP_AUTHORIZATION=f"Bearer {self.access_token}",
        )

        if response.status_code != status.HTTP_200_OK:
            print(f"Response fro reset {response.status_code}\n\n")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["message"], "Password Updated successfully")
        print(f"Response for reset password: {response.data}")

    def test_reset_password_with_invalid_user_password(self):
        response = self.client.post(
            self.reset_url,
            {
                "email": "2019kumarsatish2019@gmail.com",
                "password": "password1234",
                "new_password": "newpassword",
            },
            HTTP_AUTHORIZATION=f"Bearer {self.access_token}",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["message"], "Invalid Password.")
        print(f"Response for reset password with invalid data: {response.data}")
