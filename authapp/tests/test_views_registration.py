from rest_framework.test import APITestCase 
from rest_framework import status
from django.contrib.auth import get_user_model

class UserRegistrationTest(APITestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(
            email="nitinshenigaram7860@gmail.com",
            mobile="9172048485",
            password="nitin@#123",
        )
        self.registrationurl = "/auth/new-user-register/"

    def test_registration_user_exists(self):
        """ Test case for user_exists """
        payload = {
            "email": "nitinshenigaram7860@gmail.com",
            "password": "nitin@#123",
            "password2": "nitin@#123",
            "mobile": "9172048485"
        }
        response = self.client.post(self.registrationurl, payload, format = "json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_registration_succcessful(self):
        """ Test case for successfully registration """

        payload = { 
            "email": "nitinshenigaramc7860@gmail.com",
            "password": "nitin@#123",
            "password2": "nitin@#123",
            "mobile": "9172048485"
        }

        response = self.client.post(self.registrationurl, payload, format = 'json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
