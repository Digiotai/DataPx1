# myapp/auth_backends.py

from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import User

class EmailBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        print(f"[AUTH BACKEND] Email: {username}, Password: {password}")
        try:
            user = User.objects.get(email=username)
            if user.check_password(password):
                print(f"[AUTH BACKEND] Authenticated: {user.username}")
                return user
        except User.DoesNotExist:
            print("[AUTH BACKEND] User not found")
            return None
