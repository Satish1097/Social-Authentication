from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
import pyotp

class VerifyOTPView(APIView):
    def post(self, request, *args, **kwargs):
        mobile = request.data.get("mobile")
        email = request.data.get("email")
        user_otp = request.data.get("otp")
        
        if not mobile:
            return Response({"error": "Mobile number is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            otp_record = OTP.objects.get(mobile=mobile, is_used=False)
            totp = pyotp.TOTP(otp_record.secret_key, interval=120)
            
            if totp.verify(user_otp, valid_window=1):
                otp_record.is_used = True
                otp_record.is_verified = True
                otp_record.save()
                
                try:
                    user = User.objects.get(mobile=mobile)
                    
                    # Generate JWT tokens
                    refresh = RefreshToken.for_user(user)
                    access_token = str(refresh.access_token)
                    
                    return Response(
                        {
                            "message": "OTP verified successfully",
                            "access_token": access_token,
                            "refresh_token": str(refresh),
                        },
                        status=status.HTTP_200_OK,
                    )
                
                except User.DoesNotExist:
                    return Response({"message": "OTP verified successfully"}, status=status.HTTP_200_OK)
            else:
                return Response({"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)
        
        except OTP.DoesNotExist:
            return Response({"error": "OTP record not found or already used."}, status=status.HTTP_404_NOT_FOUND)
