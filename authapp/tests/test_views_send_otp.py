import stat
from rest_framework.test import APITestCase
from rest_framework import status
from django.core import mail
from django.test import override_settings

class SendOtpTest(APITestCase):
    def setUp(self):
        self.send_otp_url = '/auth/send-otp/'
        return super().setUp()
    

    def test_required_fields(self):
        """ Test cases for both fields are null either email or mobile. """
        payload = { 
            "email" : None,
            "mobile" : None
        }
        response = self.client.post(self.send_otp_url,payload,format = 'json')
        self.assertEqual(response.status_code,status.HTTP_400_BAD_REQUEST)
        

    def test_send_mobile_otp(self):
        """Test cases to send mobile otp."""

        payload = {
            "mobile":"9172048485"
        }
        response = self.client.post(self.send_otp_url,payload,format = 'json')
        self.assertEqual(response.status_code,status.HTTP_200_OK)
    
    @override_settings(EMAIL_BACKEND='django.core.mail.backends.smtp.EmailBackend')
    def test_send_email_otp(self):
        """Test cases to send email otp."""

        payload = {
            "email":"nitinshenigaram7860@gmail.com"
        }
  
        response = self.client.post(self.send_otp_url,payload,format = 'json')
        print("$$$"*40)
        print(response.data)
        print("$$$"*40)


        self.assertEqual(response.status_code,status.HTTP_200_OK)