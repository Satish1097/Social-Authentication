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
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode


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
        if email is not None:
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
        elif mobile is not None:
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
        auth_header = request.META.get("HTTP_AUTHORIZATION", "")

        # Check if the Authorization header is present and contains the 'Bearer' token
        if auth_header.startswith("Bearer "):
            access = auth_header[7:]  # Remove 'Bearer ' prefix
            print(f"Access Token: {access}")
        else:
            return Response(
                {"detail": "Authorization header missing or invalid."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            # Attempt to find the UserToken using the access token
            usertoken = UserToken.objects.get(access_token=access)
            # Retrieve the refresh token
            tx = usertoken.refresh_token
            # Attempt to find the OutstandingToken using the refresh token
            token = OutstandingToken.objects.get(token=tx)
            # Add the token to the blacklist and delete the outstanding token
            BlacklistedToken.objects.get_or_create(token=token)
            token.delete()
            usertoken.delete()

            return Response(
                {"detail": "Successfully logged out."},
                status=status.HTTP_205_RESET_CONTENT,
            )

        except UserToken.DoesNotExist:
            return Response(
                {"detail": "Invalid access token."}, status=status.HTTP_400_BAD_REQUEST
            )

        except OutstandingToken.DoesNotExist:
            return Response(
                {"detail": "Invalid refresh token."}, status=status.HTTP_400_BAD_REQUEST
            )


class ResetPasswordAPIView(GenericAPIView):

    def post(self, request):
        auth_header = request.META.get("HTTP_AUTHORIZATION", "")

        # Check if the Authorization header is present and contains the 'Bearer' token
        if auth_header.startswith("Bearer "):
            access_token = auth_header[7:]  # Remove 'Bearer ' prefix
            return access_token
        else:
            # Return None or raise an error if no valid token is found
            return None
        access_token = request.GET.get("access_token")
        print(access_token)
        user = request.user
        email = user.email
        password = request.data.get("password")
        new_password = request.data.get("new_password")
        try:
            user = User.objects.get(email=email)
            password = user.check_password(password)
            if password:
                user.set_password(new_password)
                user.save()
                OutstandingToken.objects.filter(user=user).delete()
                return Response(
                    {"message": "Password Updated successfully"},
                    status=status.HTTP_200_OK,
                )
            else:
                return Response("Invalid Credential")
        except User.DoesNotExist:
            return Response(status=status.HTTP_400_BAD_REQUEST)


class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer


class PasswordForgotRequestView(GenericAPIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")
        mobile = request.data.get("mobile")
        if mobile:
            try:
                user = User.objects.get(mobile=mobile)
            except User.DoesNotExist:
                return Response(
                    {"message": "User does not exist with this mobile"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        elif email:
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                return Response(
                    {"message": "User does not exist with this email"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        else:
            return Response(
                {"message": "Enter mobile or email"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        reset_link = f"http://127.0.0.1:8000/auth/password-reset-confirm/{uid}/{token}/"
        if email:
            send_mail(
                "Password Reset",
                f"Click the link to reset your password: {reset_link}",
                "settings.EMAIL_HOST_USER",  # Use settings.EMAIL_HOST_USER directly
                [email],
            )
            return Response(
                {"message": "Password reset link sent on email!"},
                status=status.HTTP_200_OK,
            )
        elif mobile:
            client = Client(os.getenv("account_sid"), os.getenv("auth_token"))
            message = client.messages.create(
                body=f"Reset Link: {reset_link}",
                from_=os.getenv(
                    "Twilio_Number"
                ),  # Twilio phone number bought using trial amount
                to=f"+91{mobile}",
            )
            return Response(
                {"message": "reset link sent on mobile!"}, status=status.HTTP_200_OK
            )
        else:
            return Response(
                {"message": "Kindly Enter mobile or email"},
                status=status.HTTP_400_BAD_REQUEST,
            )


class PasswordConfirmView(GenericAPIView):
    serializer_class = PasswordResetConfirmSerializer
    permission_classes = [AllowAny]

    def post(self, request, uidb64, token):
        try:
            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=user_id)

            if not default_token_generator.check_token(user, token):
                return Response(
                    {"error": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST
                )

            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            user.set_password(serializer.validated_data["password"])
            user.save()

            return Response(
                {"message": "Password has been reset."}, status=status.HTTP_200_OK
            )
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response(
                {"error": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST
            )


# template to check Google Authentication working or not
from django.shortcuts import render


def google_auth_test(request):
    return render(
        request,
        "index.html",
    )


def profileview(request):
    return render(request, "profile.html")
