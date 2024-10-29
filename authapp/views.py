from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny, IsAdminUser
from authapp.models import *
import pyotp
from twilio.rest import Client
import os
from django.conf import settings
from rest_framework import status
from django.core.mail import send_mail
import requests
from authapp.models import User
from rest_framework import status
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from authapp.serializers import *
from django.contrib.auth import authenticate
from rest_framework_simplejwt.token_blacklist.models import (
    BlacklistedToken,
    OutstandingToken,
)
from rest_framework_simplejwt.views import TokenObtainPairView


class VerifyAPIView(GenericAPIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        email = request.data.get("email")
        mobile = request.data.get("mobile")

        # Generate a new secret key and Time based OTP instance
        secret_key = pyotp.random_base32()  # Base32-encoded secret key
        totp = pyotp.TOTP(secret_key, interval=120)
        # Generate a 6-digit OTP
        otp = totp.now()
        if email:
            try:
                user = User.objects.get(email=email)
                return Response("Email already exists")
            except User.DoesNotExist:
                subject = "Your OTP Code"
                message = f"Your OTP is {otp}"
                from_email = settings.EMAIL_HOST_USER
                # Send the email
                send_mail(
                    subject,
                    message,
                    from_email,
                    [email],
                    fail_silently=False,
                )
                # Save the OTP record
                otp_record, _ = OTP.objects.get_or_create(email=email)
                otp_record.secret_key = secret_key
                otp_record.is_used = False
                otp_record.save()

                return Response(
                    {"message": "OTP sent on your mail"}, status=status.HTTP_200_OK
                )
        elif mobile:
            try:
                user = User.objects.get(mobile=mobile)
                return Response("Mobile already exists")
            except User.DoesNotExist:
                client = Client(os.getenv("account_sid"), os.getenv("auth_token"))
                message = client.messages.create(
                    body=f"Your OTP is {otp}",
                    from_=os.getenv(
                        "Twilio_Number"
                    ),  # Twilio phone number bought using trial amount
                    to=f"+91{mobile}",
                )
                # Save the secret key for verification later
                otp_record, _ = OTP.objects.get_or_create(mobile=mobile)
                otp_record.secret_key = secret_key
                otp_record.is_used = False
                otp_record.save()
                return Response(
                    {"message": "OTP sent successfully"}, status=status.HTTP_200_OK
                )
        else:
            return Response("Enter mobile or email")


class VerifyOTPAPIView(GenericAPIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        mobile = request.data.get("mobile")
        email = request.data.get("email")
        user_otp = request.data.get("otp")

        # Check for required fields
        if not mobile and not email:
            return Response(
                {"error": "Either mobile or email is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if not user_otp:
            return Response(
                {"error": "OTP is required."}, status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # Find the OTP record
            if mobile:
                otp_record = OTP.objects.get(mobile=mobile, is_used=False)
            else:
                otp_record = OTP.objects.get(email=email, is_used=False)
            # Initialize TOTP
            totp = pyotp.TOTP(otp_record.secret_key, interval=120)
            print(totp)
            # Verify the OTP
            if totp.verify(user_otp, valid_window=1):
                otp_record.is_used = True
                otp_record.is_verified = True
                otp_record.save()
                return Response(
                    {"message": "OTP verified successfully."}, status=status.HTTP_200_OK
                )
            else:
                return Response(
                    {"error": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST
                )
        except OTP.DoesNotExist:
            return Response(
                {"error": "OTP not found or already used."},
                status=status.HTTP_400_BAD_REQUEST,
            )


class GoogleAuthAPIView(APIView):
    def post(self, request):
        token = request.data.get("token")
        if not token:
            return Response(
                {"error": "Token is required"}, status=status.HTTP_400_BAD_REQUEST
            )
        # Verify the token with Google
        try:
            response = requests.get(
                f"https://oauth2.googleapis.com/tokeninfo?id_token={token}"
            )
            user_info = response.json()

            # Check for errors in the response
            if response.status_code != 200 or "error" in user_info:
                return Response(
                    {"error": user_info.get("error", "Invalid token")},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            email = user_info.get("email")
            if not email:
                return Response(
                    {"error": "Email not found"}, status=status.HTTP_400_BAD_REQUEST
                )

            # Create or get the user
            user, created = User.objects.get_or_create(
                email=email, defaults={"username": ""}
            )

            # Generate JWT token
            refresh = RefreshToken.for_user(user)

            return Response(
                {
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                    "email": user.email,
                },
                status=status.HTTP_200_OK,
            )

        except requests.RequestException as e:
            return Response(
                {"error": "Failed to verify token with Google"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        except Exception as e:
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class RegisterationAPIView(GenericAPIView):
    serializer_class = UserRegistrationSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutAPIView(GenericAPIView):

    def post(self, request):
        tokens = OutstandingToken.objects.filter(user_id=request.user.id)
        for token in tokens:
            BlacklistedToken.objects.get_or_create(token=token)
            token.delete()

        return Response(status=status.HTTP_205_RESET_CONTENT)


class ResetPasswordAPIView(GenericAPIView):
    pass


class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer


# template to check Google Authentication working or not
from django.shortcuts import render


def google_auth_test(request):
    return render(
        request,
        "index.html",
    )


def profileview(request):
    return render(request, "profile.html")
