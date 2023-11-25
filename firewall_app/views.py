from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse

from .forms import FirewallRuleForm
from .models import FirewallRule

def firewall_rules(request):
    rules = FirewallRule.objects.all()

    if request.method == 'POST':
        form = FirewallRuleForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('firewall_rules')  # Redirect to the same page after adding a rule
    else:
        form = FirewallRuleForm()

    return render(request, 'firewall_app/firewall_rules.html', {'rules': rules, 'form': form})

def delete_rule(request, rule_id):
    rule = get_object_or_404(FirewallRule, id=rule_id)
    rule.delete()
    return redirect('firewall_rules')  # Redirect to the firewall rules page after deleting a rule

def index(request):
    return HttpResponse("Hello, world. You're at the firewall-app index.")