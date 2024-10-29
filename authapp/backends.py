from django.contrib.auth.backends import BaseBackend
from django.contrib.auth import get_user_model

User = get_user_model()


class EmailOrMobileBackend(BaseBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        if username is None or password is None:
            return None

        try:
            # Check if username is an email or a mobile number
            user = (
                User.objects.get(email=username)
                if "@" in username
                else User.objects.get(mobile=username)
            )
        except User.DoesNotExist:
            return None

        # Check password
        if user.check_password(password) and self.user_can_authenticate(user):
            return user
        return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

    def user_can_authenticate(self, user):
        """
        Determine if the user can authenticate.
        This checks the user's active status.
        """
        is_active = getattr(user, "is_active", None)
        return is_active or is_active is None
