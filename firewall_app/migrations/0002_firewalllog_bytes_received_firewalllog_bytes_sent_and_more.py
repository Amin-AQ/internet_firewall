# Generated by Django 4.2.7 on 2023-11-26 13:52

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('firewall_app', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='firewalllog',
            name='bytes_received',
            field=models.PositiveBigIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='firewalllog',
            name='bytes_sent',
            field=models.PositiveBigIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='firewalllog',
            name='no_of_packets',
            field=models.PositiveIntegerField(default=0),
        ),
    ]
