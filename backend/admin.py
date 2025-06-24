from django.contrib import admin
from .models import Tenant, Organization, UserRole, AuditLog, EmailOTP


@admin.register(Tenant)
class TenantAdmin(admin.ModelAdmin):
    list_display = ('name', 'type', 'created_at')
    search_fields = ('name', 'type')


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ('name', 'tenant', 'parent')
    search_fields = ('name',)
    list_filter = ('tenant',)


@admin.register(UserRole)
class UserRoleAdmin(admin.ModelAdmin):
    list_display = ('user', 'organization', 'role')
    search_fields = ('user__email', 'organization__name')
    list_filter = ('role',)


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('user', 'action', 'entity_type', 'timestamp')
    search_fields = ('user__email', 'entity_type', 'action')
    list_filter = ('action', 'entity_type')


@admin.register(EmailOTP)
class EmailOTPAdmin(admin.ModelAdmin):
    list_display = ('user', 'otp', 'created_at')
