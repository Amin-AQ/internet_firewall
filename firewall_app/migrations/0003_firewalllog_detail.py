# Generated by Django 4.2.7 on 2023-12-05 10:48

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('firewall_app', '0002_firewalllog_bytes_received_firewalllog_bytes_sent_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='firewalllog',
            name='detail',
            field=models.CharField(default=1, max_length=100),
            preserve_default=False,
        ),
    ]
