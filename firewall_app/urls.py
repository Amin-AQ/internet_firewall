from django.urls import path

from . import views
from .views import firewall_rules

urlpatterns = [
    path("", views.index, name="index"),
    path('firewall_rules/', firewall_rules, name='firewall_rules'),
    path('delete_rule/<int:rule_id>/', views.delete_rule, name='delete_rule'),
]