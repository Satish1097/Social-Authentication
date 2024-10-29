from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework import status
from rest_framework.response import Response
from django.contrib.auth import authenticate

class CustomTokenObtainPairView(TokenObtainPairView):
    def post(self, request, *args, **kwargs):
        email = request.data.get("email")
        password = request.data.get("password")

        # Authenticate the user
        user = authenticate(request, username=email, password=password)

        if user is not None:
            # If user is authenticated, call the super method to generate tokens
            return super().post(request, *args, **kwargs)
        else:
            # Return an error response if authentication fails
            return Response({"detail": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

# In your urls.py, register the view
from django.urls import path

urlpatterns = [
    path('api/token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
]


from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken

class LogoutAPIView(GenericAPIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Retrieve outstanding tokens for the authenticated user
        tokens = OutstandingToken.objects.filter(user_id=request.user.id)
        
        if not tokens.exists():
            return Response({"detail": "No active sessions to logout."}, status=status.HTTP_400_BAD_REQUEST)

        # Blacklist each token
        for token in tokens:
            # You need to create a BlacklistedToken instance
            BlacklistedToken.objects.create(token=token)
            token.delete()  # Optionally delete outstanding token

        return Response(status=status.HTTP_205_RESET_CONTENT)
