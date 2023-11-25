# firewall_app/forms.py
from django import forms
from django.core.exceptions import ValidationError
import ipaddress

from .models import FirewallRule

class FirewallRuleForm(forms.ModelForm):
    class Meta:
        model = FirewallRule
        fields = ['src_ip', 'dest_ip', 'src_port', 'dest_port', 'protocol', 'action']

    def clean_src_ip(self):
        src_ip = self.cleaned_data['src_ip']

        if not is_valid_ip(src_ip):
            raise ValidationError("Invalid source IP address.")
        return src_ip

    def clean_dest_ip(self):
        dest_ip = self.cleaned_data['dest_ip']

        if not is_valid_ip(dest_ip):
            raise ValidationError("Invalid destination IP address.")
        return dest_ip

    def clean_src_port(self):
        src_port = self.cleaned_data['src_port']

        if not is_valid_port(src_port):
            raise ValidationError("Invalid source port.")
        return src_port

    def clean_dest_port(self):
        dest_port = self.cleaned_data['dest_port']

        if not is_valid_port(dest_port):
            raise ValidationError("Invalid destination port.")
        return dest_port


def is_valid_port(port_):
    return port_ > 0

def is_valid_ip(value):
    try:
        ipaddress.IPv4Address(value)
        return True
    except ipaddress.AddressValueError:
        return False