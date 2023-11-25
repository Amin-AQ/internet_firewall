# models.py
from django.db import models
from django import forms


class FirewallRule(models.Model):
    priority = models.PositiveIntegerField(default=0)
    src_ip = models.GenericIPAddressField(default='0.0.0.0')  # Default is 'any'
    dest_ip = models.GenericIPAddressField(default='0.0.0.0')  # Default is 'any'
    src_port = models.IntegerField(default=-1)  # Default is 'any'
    dest_port = models.IntegerField(default=-1)  # Default is 'any'
    
    PROTOCOL_CHOICES = [
    ('tcp', 'Tcp'),
    ('udp', 'Udp'),
    ('any', 'Any'),
    ]

    ACTION_CHOICES = [
        ('allow', 'Allow'),
        ('deny', 'Deny'),
    ]
    action = models.CharField(max_length=5, choices=ACTION_CHOICES, default='deny')  # Default is 'allow'

    protocol = models.CharField(max_length=3, choices=PROTOCOL_CHOICES, default='any')  # Default is 'allow'

    def __str__(self):
        return f"{self.priority} - {self.src_ip} to {self.dest_ip} ({self.protocol}): {self.action}"


class FirewallLog(models.Model):
    src_ip = models.GenericIPAddressField()
    dest_ip = models.GenericIPAddressField()
    src_port = models.PositiveIntegerField()
    dest_port = models.PositiveIntegerField()
    protocol = models.CharField(max_length=10)
    action = models.CharField(max_length=10)
    timestamp = models.DateTimeField(auto_now_add=True)
