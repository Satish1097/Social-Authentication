from rest_framework.test import APITestCase
from django.urls import reverse
from authapp.models import OTP


class TestSetUp(APITestCase):
    def setUp(self):
        self.register_url = reverse("register")
        self.login_url = reverse("login")

        self.user_data = {
            "email": "2019kumarsatish2019@gmail.com",
            "password": "12345678wertyu",
            "password2": "12345678wertyu",
            "username": "SatishKumar",
        }
        # Create a valid OTP for email and mobile (simulate OTP verification)
        OTP.objects.create(email="2019kumarsatish2019@gmail.com", is_used=True)
        OTP.objects.create(mobile="1234567890", is_used=True)
        return super().setUp()

    def tearDown(self):
        return super().tearDown()
