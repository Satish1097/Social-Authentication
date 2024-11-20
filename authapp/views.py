from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from authapp.models import *
import pyotp
from twilio.rest import Client
import os
from django.conf import settings
from rest_framework import status
from django.core.mail import send_mail
import requests
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
                return Response(
                    {"message": "Email already exists"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
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
                    {"message": "OTP sent to your email"}, status=status.HTTP_200_OK
                )
        elif mobile is not None:
            try:
                user = User.objects.get(mobile=mobile)
                return Response(
                    {"message": "Mobile number already exists"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
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
                    {"message": "OTP sent successfully to your mobile"},
                    status=status.HTTP_200_OK,
                )
        else:
            return Response(
                {"message": "Please provide either email or mobile number"},
                status=status.HTTP_400_BAD_REQUEST,
            )


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
            if mobile:
                otp_records = OTP.objects.filter(mobile=mobile, is_used=False)
            else:
                otp_records = OTP.objects.filter(email=email, is_used=False)
            if not otp_records.exists():
                return Response(
                    {"error": "OTP not found or already used."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            otp_record = otp_records.first()
            # Initialize TOTP
            totp = pyotp.TOTP(otp_record.secret_key, interval=120)
            new_otp = totp.now()
            # Verify the OTP
            if totp.verify(user_otp, valid_window=1):
                otp_record.is_used = True
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
                status=status.HTTP_404_NOT_FOUND,
            )


class GoogleAuthAPIView(APIView):
    permission_classes = [AllowAny]

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
        # Initialize the serializer with the request data
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            # Extract email and mobile from validated data
            email = serializer.validated_data.get("email")
            mobile = serializer.validated_data.get("mobile")

            # OTP validation for email and mobile
            if not self.is_otp_validated(email, mobile):
                return Response(
                    {"message": "Email or phone number not validated."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # If OTP is validated, create the user
            user = serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        # If serializer is invalid, return errors
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def is_otp_validated(self, email, mobile):
        # Check if OTP has been validated for email or mobile
        otp_email_validated = OTP.objects.filter(email=email, is_used=True).exists()
        otp_mobile_validated = OTP.objects.filter(mobile=mobile, is_used=True).exists()

        return otp_email_validated or otp_mobile_validated


class LogoutAPIView(GenericAPIView):
    def post(self, request):
        auth_header = request.META.get("HTTP_AUTHORIZATION", "")

        # Check if the Authorization header is present and contains the 'Bearer' token
        if auth_header.startswith("Bearer "):
            access = auth_header[7:]  # Remove 'Bearer ' prefix
        else:
            return Response(
                {"message": "Authorization header missing or invalid."},
                status=status.HTTP_401_UNAUTHORIZED,
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
                {"message": "Successfully logged out."},
                status=status.HTTP_200_OK,
            )

        except UserToken.DoesNotExist:
            return Response(
                {"message": "token_not_valid"},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        except OutstandingToken.DoesNotExist:
            return Response(
                {"message": "Invalid refresh token."},
                status=status.HTTP_401_UNAUTHORIZED,
            )


class ResetPasswordAPIView(GenericAPIView):

    def post(self, request):
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
                return Response(
                    {"message": "Invalid Password."}, status=status.HTTP_400_BAD_REQUEST
                )
        except User.DoesNotExist:
            return Response(status=status.HTTP_400_BAD_REQUEST)


class CustomTokenObtainPairView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = CustomTokenObtainPairSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        mobile = serializer.validated_data.get("mobile", None)
        email = serializer.validated_data.get("email", None)
        password = serializer.validated_data.get("password")

        # Authenticate the user
        user = None
        if email:
            user = authenticate(request=request, email=email, password=password)
        elif mobile:
            user = authenticate(request=request, username=mobile, password=password)

        if user is None:
            return Response(
                {"detail": "No active account found with the given credentials."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # Generate tokens
        refresh = RefreshToken.for_user(user)
        access_token = refresh.access_token

        # Store the tokens (optional step depending on your business logic)
        UserToken.objects.create(
            refresh_token=str(refresh), access_token=str(access_token)
        )

        return Response(
            {
                "refresh": str(refresh),
                "access": str(access_token),
            },
            status=status.HTTP_200_OK,
        )


class CustomTokenRefreshView(APIView):
    def post(self, request):
        try:
            refresh_token = request.data.get("refresh")
            if not refresh_token:
                return Response(
                    {"detail": "Refresh token is required"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Validate and get the new access token
            new_token = RefreshToken(refresh_token)
            user_token = UserToken.objects.filter(refresh_token=new_token).first()
            x = str(new_token.access_token)
            user_token.access_token = x
            user_token.save()
            return Response(
                {"access": x},
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


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
                {"message": "Enter either mobile or email"},
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
                fail_silently=True,
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
