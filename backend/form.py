from django.forms import ModelForm
from django.contrib.auth.forms import UserCreationForm
from django import forms
from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model
from .models import Tenant, Organization, UserRole, Roles, Sessions


User = get_user_model()


class PlaceholderMixin:
    def __init__(self, *args, **kwargs):
        try:
            super().__init__(*args, **kwargs)
            field_names = [field_name for field_name, _ in self.fields.items()]
            for field_name in field_names:
                field = self.fields.get(field_name)
                field.widget.attrs.update({'placeholder': field.label})
        except Exception as e:
            print(e)


class CreateUserForm(ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)

    organization = forms.CharField(required=False)
    roles = forms.CharField(required=False)

    class Meta:
        try:
            model = User
            fields = ['username', 'email', 'password']
        except Exception as e:
            print(e)

    def clean_organization(self):
        org_id = self.cleaned_data.get('organization')
        if not org_id:
            raise ValidationError("Organization ID is required")

        try:
            return Organization.objects.get(id=org_id)
        except (Organization.DoesNotExist, ValueError):
            raise ValidationError("Invalid or non-existent organization ID.")

    def clean_roles(self):
        raw = self.cleaned_data.get('roles')
        if not raw:
            return []
        roles = [r.strip() for r in raw.split(',') if r.strip()]
        # valid_choices = [choice[0].lower() for choice in UserRole.ROLE_CHOICES]
        # invalid = [r for r in roles if r.lower() not in valid_choices]
        # if invalid:
        #     raise ValidationError(f"Invalid roles: {', '.join(invalid)}. Allowed: {', '.join(valid_choices)}")
        return roles

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise ValidationError("This email address is already in use.")
        return email

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password"])  # Hash the password
        if commit:
            user.save()
        return user


class TenantForm(ModelForm):
    class Meta:
        model = Tenant
        fields = ['name', 'type']


class OrganizationForm(ModelForm):
    class Meta:
        model = Organization
        fields = ['tenant', 'name', 'parent', 'image_name', 'image_data']


class UserRoleForm(ModelForm):
    class Meta:
        model = UserRole
        fields = ['user', 'organization', 'role']


class RolesForm(ModelForm):
    class Meta:
        model = Roles
        fields = ['role', 'permissions', 'organization']


class SessionsForm(ModelForm):
    class Meta:
        model = Sessions
        fields = ['userId', 'userName', 'userEmail', "orgId", "ipAddress", "deviceInfo", "loginTime"]
