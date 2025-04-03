from operator import truediv
from xmlrpc.client import ResponseError
from rest_framework.test import APITestCase
from rest_framework import status

from authapp.models import User

class ResetPasswordTest(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="nitinshenigaram7860@gmail.com",
            mobile="9172048485",
            password="nitin@#123",
        )

        self.user.is_email_verified = True
        self.user.is_mobile_verified = True
        self.user.save()
        print(self.user.password)
        self.login_url = '/auth/new-login/'
        response = self.client.post(self.login_url, {'email':'nitinshenigaram7860@gmail.com','password':'nitin@#123'})

        self.access_token = response.data.get('access')
        self.refresh_token = response.data.get('refresh')

        self.headers = {"Authorization": f"Bearer {self.access_token}"}

        self.reset_password_url = '/auth/reset_password/'

        return super().setUp()

    def test_authentication_credentials_not_provided(self):
        """ test case for authentication credentials not provided """
        response = self.client.post(self.reset_password_url,{},format='json')
        self.assertEqual(response.status_code,status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data['detail'],'Authentication credentials were not provided.')
    
    def test_invalid_password(self):
        """ test case for invalid password """

        response = self.client.post(self.reset_password_url,{},format='json',headers=self.headers)
        self.assertEqual(response.status_code,status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data.get('message'),'Invalid Password.')
    
    def test_reset_passwor_successful(self):
        """ TestCase for reset password successful """

        response = self.client.post(
            self.reset_password_url,
            {'password':'nitin@#123','new_password':'1234'},
            format='json',
            headers=self.headers
        )
        self.assertEqual(response.status_code,status.HTTP_200_OK)
        self.assertEqual(response.data.get('message'),'Password Updated successfully')

        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('1234'))

        # login with new password
        response = self.client.post(
            self.login_url, {'email': 'nitinshenigaram7860@gmail.com', 'password': '1234'}, format='json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)
  