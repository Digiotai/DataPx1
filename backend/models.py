from django.db import models
from django.contrib.auth.models import User
import random
from django.contrib.postgres.fields import ArrayField,JSONField
import uuid
from django.db import models


class EmailOTP(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def generate_otp(self):
        self.otp = str(random.randint(100000, 999999))
        self.save()

    def is_valid(self, otp_input):
        """Check if OTP matches and is within 5 minutes."""
        return self.otp == otp_input


class Tenant(models.Model):
    TYPE_CHOICES = [
        ('ai-priori', 'AI-Priori'),
        ('oem', 'OEM'),
        ('customer', 'Customer'),
    ]
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    type = models.CharField(max_length=20, choices=TYPE_CHOICES)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} ({self.type})"


class Organization(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    parent = models.ForeignKey('self', null=True, blank=True, on_delete=models.SET_NULL)
    image_data = models.BinaryField(null=True, blank=True, editable=True)
    image_name = models.CharField(max_length=255, null=True, blank=True)

    def __str__(self):
        return self.name


class Roles(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    role = models.CharField(max_length=255)
    permissions = ArrayField(models.CharField(max_length=255))
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, null=True)


class Sessions(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    userId = models.CharField(max_length=255)
    userName = models.CharField(max_length=255)
    userEmail = models.CharField(max_length=255)
    orgId = models.CharField(max_length=255)
    ipAddress = models.CharField(max_length=255)
    deviceInfo = models.CharField(max_length=255)
    loginTime = models.DateTimeField(max_length=255)
    logoutTime = models.DateTimeField(max_length=255, null=True)
    durationMinutes = models.FloatField(max_length=255, null=True)
    status = models.CharField(max_length=255)


class UserRole(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, null=True)
    role = ArrayField(models.CharField(max_length=20))

    def __str__(self):
        return f"{self.user.email} - {self.role}"


class AuditLog(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    action = models.CharField(max_length=255)
    entity_type = models.CharField(max_length=50)
    entity_id = models.UUIDField()
    timestamp = models.DateTimeField(auto_now_add=True)
    details = models.JSONField(null=True, blank=True)

    def __str__(self):
        return f"{self.timestamp}: {self.user} - {self.action} on {self.entity_type}"


class ChatSession(models.Model):
    session_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_id = models.CharField(max_length=100)
    base_context = models.TextField(blank=True, null=True)
    csv_file = models.CharField(max_length=500, null=True, blank=True)
    csv_columns = models.JSONField(null=True, blank=True)
    csv_stats = models.JSONField(null=True, blank=True)
    session_name = models.CharField(max_length=255, blank=True, null=True)  # Optional label
    created_at = models.DateTimeField(auto_now_add=True)


class ChatMessage(models.Model):
    session = models.ForeignKey(ChatSession, on_delete=models.CASCADE, related_name='messages')
    query = models.TextField()
    response = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    token_count = models.IntegerField(null=True, blank=True)
