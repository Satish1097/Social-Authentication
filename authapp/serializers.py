from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from authapp.models import *
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()


class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True, required=True, validators=[validate_password]
    )
    password2 = serializers.CharField(write_only=True, required=True)
    mobile = serializers.CharField(required=False, allow_blank=True)

    class Meta:
        model = User
        fields = ["email", "password", "password2", "mobile", "username"]

    def validate(self, attrs):
        if attrs["password"] != attrs["password2"]:
            raise serializers.ValidationError(
                {"password": "Password fields didn't match."}
            )
        return attrs

    def create(self, validated_data):
        validated_data.pop("password2")
        email = validated_data.get("email")
        mobile = validated_data.get("mobile")
        otpemail = OTP.objects.filter(email=email, is_verified=True).exists()
        otpmobile = OTP.objects.filter(mobile=mobile, is_verified=True).exists()

        if otpemail or otpmobile:

            user = User.objects.create(
                email=email,
                mobile=mobile,
                username=validated_data.get("username", ""),
            )
            user.set_password(validated_data["password"])
            user.save()
            return user
        else:
            raise serializers.ValidationError("Email or phone not Validated")


class CustomTokenObtainPairSerializer(serializers.Serializer):
    mobile = serializers.CharField(required=False)
    email = serializers.EmailField(required=False)
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        mobile = attrs.get("mobile", None)
        email = attrs.get("email", None)
        password = attrs.get("password")

        if not (mobile or email):
            raise serializers.ValidationError(
                "Please provide either a mobile number or an email address."
            )

        # Authenticate using email or mobile
        user = None
        if email:
            user = authenticate(
                request=self.context.get("request"), email=email, password=password
            )
        elif mobile:
            user = authenticate(
                request=self.context.get("request"), username=mobile, password=password
            )  # Ensure 'username' is used here

            print(user)

        if user is None:
            raise serializers.ValidationError(
                "No active account found with the given credentials."
            )

        # Generate tokens
        refresh = RefreshToken.for_user(user)
        return {
            "refresh": str(refresh),
            "access": str(refresh.access_token),
            "user_id": user.id,  # Optional: Include user ID in response
        }
