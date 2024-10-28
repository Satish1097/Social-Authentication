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


class VerifyAPIView(GenericAPIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        email = request.data.get("email")
        mobile = request.data.get("mobile")

        if not email and not mobile:
            return Response(
                {"error": "Enter Valid Data"}, status=status.HTTP_400_BAD_REQUEST
            )

        # Check if user with provided email or mobile already exists
        if email:
            if User.objects.filter(email=email).exists():
                return Response(
                    "Email already exists", status=status.HTTP_400_BAD_REQUEST
                )
        if mobile:
            if User.objects.filter(mobile=mobile).exists():
                return Response(
                    "Mobile number already exists", status=status.HTTP_400_BAD_REQUEST
                )

        # Check if OTP has already been verified
        otp_record = (
            OTP.objects.filter(email=email).first()
            if email
            else OTP.objects.filter(mobile=mobile).first()
        )
        if otp_record and otp_record.is_verified:
            return Response(
                "Email or mobile is already verified", status=status.HTTP_200_OK
            )

        # Generate a new secret key and OTP
        secret_key = pyotp.random_base32()
        totp = pyotp.TOTP(secret_key, interval=120)
        otp = totp.now()

        if email:
            try:
                subject = "Your OTP Code"
                message = f"Your OTP is {otp}"
                from_email = settings.EMAIL_HOST_USER
                send_mail(subject, message, from_email, [email], fail_silently=False)

                otp_record, _ = OTP.objects.get_or_create(email=email)
                otp_record.secret_key = secret_key
                otp_record.is_used = False
                otp_record.save()

                return Response(
                    {"message": "OTP sent to your email"}, status=status.HTTP_200_OK
                )
            except Exception as e:
                return Response(
                    {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

        elif mobile:
            try:
                client = Client(os.getenv("account_sid"), os.getenv("auth_token"))
                message = client.messages.create(
                    body=f"Your OTP is {otp}",
                    from_=os.getenv("Twilio_Number"),
                    to=f"+91{mobile}",
                )

                otp_record, _ = OTP.objects.get_or_create(mobile=mobile)
                otp_record.secret_key = secret_key
                otp_record.is_used = False
                otp_record.save()

                return Response(
                    {"message": "OTP sent to your mobile"}, status=status.HTTP_200_OK
                )
            except Exception as e:
                return Response(
                    {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )


class VerifyOTPAPIView(GenericAPIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        mobile = request.data.get("mobile")
        email = request.data.get("email")
        user_otp = request.data.get("otp")
        try:
            if mobile:
                otp_record = OTP.objects.get(mobile=mobile, is_used=False)
            else:
                otp_record = OTP.objects.get(email=email, is_used=False)
        except OTP.DoesNotExist:
            return Response(
                {"error": "OTP not found or already used"},
                status=status.HTTP_404_NOT_FOUND,
            )
        if otp_record:
            totp = pyotp.TOTP(otp_record.secret_key, interval=120)

            if totp.verify(
                user_otp, valid_window=1
            ):  # valid window add 30 second before and after in actual time to validate the otp
                otp_record.is_used = True
                otp_record.is_verified = True
                otp_record.save()
                return Response(
                    {
                        "message": "OTP verified successfully",
                    },
                    status=status.HTTP_200_OK,
                )
            else:
                return Response(
                    {"message": "OTP verification failed"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        else:
            return Response(
                {"error": "Invalid OTP provided"}, status=status.HTTP_400_BAD_REQUEST
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


# template to check Google Authentication working or not
from django.shortcuts import render
from django.http import HttpResponse


def google_auth_test(request):
    return render(
        request,
        "index.html",
    )
