from django.apps import AppConfig


class BackendConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'backend'

    def ready(self):
        from django.contrib.auth.models import User
        from django.core.validators import RegexValidator

        # Override the model-level validator
        User._meta.get_field('username').validators = [
            RegexValidator(
                regex=r'^[\w -]+$',
                message='Username can only contain letters, digits, underscores, and spaces.'
            )
        ]
