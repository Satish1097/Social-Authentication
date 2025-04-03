from unittest import TestCase
from rest_framework.test import APITestCase
from rest_framework import status
from django.contrib.auth import get_user_model


class UserLoginTest(APITestCase):
    def setUp(self):
        """Setup test user"""
        User = get_user_model()
        self.user = User.objects.create_user(email="testuser@gmail.com", password="testpass")
        self.user.is_email_verified = True  # Ensure the user is verified
        self.user.is_mobile_verified = True
        self.user.save()
        self.login_url = "/auth/new-login/"


    def test_login_success(self):
        """Test login with valid credentials"""
        data = {"email": "testuser@gmail.com", "password": "testpass"}
        response = self.client.post(self.login_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)  

    def test_login_failure(self):

        """Test login with empty email, password, and mobile"""
        payload = {
            'email':None,
            'password':None
        }
        response = self.client.post(self.login_url, payload, format="json")


        """ Testcase for email if it is empty """
        if payload['email'] is None:
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
            self.assertEqual(response.data['email'], ["This field may not be null."])

        """ Testcase for email and password if they are empty """
        if payload['email'] and payload['password']:
            self.assertEqual(response.status_code,status.HTTP_400_BAD_REQUEST)
            self.assertEqual(response.data['email'],["This field may not be null."])
            self.assertEqual(response.data['password'],["This field may not be null."])
        
        
        


        """Test login with invalid credentials"""
        data = {"email": "testuser@gmail.com", "password": "wrongpass"}  
        response = self.client.post(self.login_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        
        """Test login with unverified email"""
        self.user.is_email_verified = False
        self.user.save()
        data = {"email": "testuser@gmail.com", "password": "testpass"}
        response = self.client.post(self.login_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data["message"], "Email or mobile not verified")


