from django.apps import AppConfig
from django.conf import settings
import threading
class FirewallAppConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'firewall_app'

    def ready(self):
        # Import here to avoid circular imports
        from .management.commands.sniffer import start_sniffer, stop_sniffer
        from .management.commands import utils
        utils.initialize_model(settings.BASE_DIR)
        # Start sniffer when the Django server starts
        sniffer_thread = threading.Thread(target=start_sniffer)
        sniffer_thread.daemon = True  # Daemonize the thread so it's terminated when the main program exits
        sniffer_thread.start()

