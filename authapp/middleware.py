# import jwt
# import time
# import os
# import logging
# from dotenv import load_dotenv
# from django.http import JsonResponse
# from authapp.models import User
# from jwt.exceptions import InvalidSignatureError, ExpiredSignatureError, PyJWTError

# logger = logging.getLogger(__name__)
# load_dotenv()


# class TokenAuthenticationMiddleware:
#     def __init__(self, get_response):
#         self.get_response = get_response

#     def __call__(self, request):

#         if not request.path.startswith("/auth"):
#             return self.get_response(request)

#         # Get the JWT token from the request headers
#         authorization_header = request.META.get("HTTP_AUTHORIZATION")

#         if authorization_header and authorization_header.startswith("Bearer "):
#             token = authorization_header.split("Bearer ")[1]

#             # Decode the JWT token manually
#             try:
#                 # Decode the JWT token
#                 decoded_token = jwt.decode(
#                     token, os.getenv("JWT_SECRET_KEY"), algorithms=["HS256"]
#                 )
#             except InvalidSignatureError:
#                 # The signature of the JWT token does not match the secret key
#                 logger.warning("Invalid token")
#                 return JsonResponse({"error": "Invalid token"}, status=401)
#             except ExpiredSignatureError:
#                 # The JWT token has expired
#                 logger.warning("Expired token")
#                 return JsonResponse({"error": "Expired token"}, status=401)
#             except PyJWTError:
#                 # Other JWT-related errors
#                 logger.warning("Invalid token")
#                 return JsonResponse({"error": "Invalid token"}, status=401)

#             # Verify the JWT token
#             if decoded_token["exp"] < time.time():
#                 return JsonResponse({"error": "Expired token"}, status=401)

#             # Check if the user exists in your system
#             user_id = decoded_token.get("user_id")

#             try:
#                 user = User.objects.get(pk=user_id)
#                 logger.info(f"user - {user.email}")

#             except Exception as e:
#                 return JsonResponse({"error": "User not found"}, status=401)
#         else:
#             return JsonResponse(
#                 {"error": "Authorization header missing or invalid"}, status=401
#             )

#         # If the JWT token is valid and the user exists, you can proceed with the request
#         # You can also attach the user object to the request for further use in the view
#         request.authUserData = user

#         response = self.get_response(request)
#         return response


# middleware.py
from django.utils.deprecation import MiddlewareMixin
from rest_framework.exceptions import AuthenticationFailed
from .models import UserDeviceToken


class TokenBlacklistMiddleware(MiddlewareMixin):
    def process_request(self, request):
        auth_header = request.META.get("HTTP_AUTHORIZATION")
        if auth_header and auth_header.startswith("Bearer "):
            token_id = auth_header.split(" ")[1]  # Get the token part
            print(token_id)
            try:
                user_token = UserDeviceToken.objects.get(token_id=token_id)
                if user_token.blacklisted:
                    raise AuthenticationFailed("This token has been blacklisted.")
            except UserDeviceToken.DoesNotExist:
                raise AuthenticationFailed("Invalid token.")
