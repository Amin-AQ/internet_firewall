from django.urls import path

from . import views

urlpatterns = [
    path('', views.HomePageView.as_view(), name='home'),
    path('firewall_logs/', views.firewall_logs, name='firewall_logs'),
    path('firewall_rules/', views.firewall_rules, name='firewall_rules'),
    path('delete_rule/<int:rule_id>/', views.delete_rule, name='delete_rule'),
    path('move_rule/<int:rule_id>/<direction>/', views.move_rule, name='move_rule'),
]