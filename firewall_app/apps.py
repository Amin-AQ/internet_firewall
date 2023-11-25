from django.apps import AppConfig

class FirewallAppConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'firewall_app'

    def ready(self):
        # Import here to avoid circular imports
        from .management.commands.sniffer import start_sniffer, stop_sniffer

        # Start sniffer when the Django server starts
        start_sniffer()

