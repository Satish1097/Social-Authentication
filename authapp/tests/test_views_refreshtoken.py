import email
from rest_framework.test import APITestCase
from rest_framework import status
from authapp.models import User


class RefreshtokenTest(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="nitinshenigaram7860@gmail.com",
            password="TestPassword123"
        )
        self.user.is_email_verified = True
        self.user.is_mobile_verified = True
        self.user.save()

        self.refreshtoken_url = '/auth/token/refresh/'
        self.login_url = '/auth/new-login/'

        response = self.client.post(self.login_url,{'email':'nitinshenigaram7860@gmail.com','password':'TestPassword123'})
        print(response.data)
        self.access_token = response.data.get('access')
        self.refresh_token = response.data.get('refresh')
        self.headers = {"Authorization": f"Bearer {self.access_token}"}

        return super().setUp()
    
    def test_refresh_field_required(self):
        """ Test Case for refresh field is need """
        print(self.headers)
        response = self.client.post(self.refreshtoken_url,{},format='json',headers=self.headers)
        self.assertEqual(response.status_code,status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['detail'],'Refresh token is required')
    
    def test_authentication_credentials_not_provided(self):
        """ test case for authentication credentials not provided """
        response = self.client.post(self.refreshtoken_url,{},format='json')
        self.assertEqual(response.status_code,status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data['detail'],'Authentication credentials were not provided.')
    

    def test_refreshtoken_succcess(self):
        """ Test refresh token success """
        response = self.client.post(self.refreshtoken_url,{'refresh':self.refresh_token},headers=self.headers)
        self.assertEqual(response.status_code,status.HTTP_200_OK)
        self.assertIn('access',response.data)