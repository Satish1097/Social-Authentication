from urllib import response
from rest_framework.test import APITestCase
from rest_framework import status
from authapp.models import User
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator

class ConfirmForgotPasswordTest(APITestCase):

    def setUp(self):
        self.user = User.objects.create(mobile="9172048485", email="nitinshenigaram7860@gmail.com")

        # Generate UID and Token
        self.uidb64 = urlsafe_base64_encode(force_bytes(self.user.pk))
        self.token = default_token_generator.make_token(self.user)

        # Dynamic URL
        self.confirm_forgot_password_url = f"/auth/password-reset-confirm/{self.uidb64}/{self.token}/"
        
        return super().setUp()

    def test_password_field_required(self):
        """Test if password field is required in reset password confirmation."""

        response = self.client.post(self.confirm_forgot_password_url, {}, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['password'],["This field is required."])

    def test_invalid_token(self):
        """ Testcase for invalid token """
        invalid_url = f"/auth/password-reset-confirm/{self.uidb64}/invalidtoken/"
        payload={
            "password":"Nitin@#123"
        }
        response = self.client.post(invalid_url,payload,format='json')
        self.assertEqual(response.status_code,status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'],"Invalid token.")

    def test_invalid_uuid(self):
        """ testcase for invalid uuid """
        invalid_uudi =  urlsafe_base64_encode(force_bytes(9999))
        url = f"/auth/password-reset-confirm/{invalid_uudi}/{self.token}/"

        response = self.client.post(url,{'password':"newpasswrod"},format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'],"Invalid token.")

    def test_password_reset_success(self):
        """ Testcase for password Reset Success """

        response = self.client.post(self.confirm_forgot_password_url,{"password":"1234"},format='json')
        self.assertEqual(response.status_code,status.HTTP_200_OK)
        self.assertEqual(response.data['message'],'Password has been reset.')


        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('1234'))