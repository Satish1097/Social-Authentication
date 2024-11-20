from rest_framework import status
from rest_framework.test import APITestCase
from django.urls import reverse
from authapp.models import *
from rest_framework import status


class LoginTestCase(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="2019kumarsatish2019@gmail.com", password="123", mobile="7762019670"
        )

    def test_login_user_with_valid_data_email_and_password(self):
        response = self.client.post(
            reverse("login"),
            {"email": "2019kumarsatish2019@gmail.com", "password": "123"},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        print(f"Login email & Password: {response.data}\n\n")

    def test_login_user_with_valid_data_mobile_and_password(self):
        response = self.client.post(
            reverse("login"),
            {"mobile": "7762019670", "password": "123"},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        print(f"Login mobile & Password: {response.data}\n\n")

    def test_login_user_with_no_data(self):
        response = self.client.post(reverse("login"), {})

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        print(f"\nLogin with No Data: {response.data}\n\n")

    def test_login_user_with_invalid_data(self):
        response = self.client.post(
            reverse("login"),
            {"email": "2019kumarsatish2019@gmail.com", "password": "2345678"},
        )

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        print(f"\nInvalid Data Response: {response.data}\n\n")
