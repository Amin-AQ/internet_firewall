from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse
from django.views.generic import TemplateView
from django.views.decorators.http import require_POST
from django.db.models import Max

from .forms import FirewallRuleForm
from .models import FirewallRule, FirewallLog

class HomePageView(TemplateView):
    template_name = 'firewall_app/index.html'


def firewall_logs(request):
    logs = FirewallLog.objects.all()
    return render(request, 'firewall_app/firewall_logs.html', {'logs': logs})

def firewall_rules(request):
    rules = FirewallRule.objects.order_by('priority') 
    max_priority = FirewallRule.objects.aggregate(Max('priority'))['priority__max']
    
    default_priority = max_priority + 1 if max_priority is not None else 0
    if request.method == 'POST':
        form = FirewallRuleForm(request.POST)
        if form.is_valid():
            form.instance.priority = default_priority
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


@require_POST
def move_rule(request, rule_id, direction):
    rule = get_object_or_404(FirewallRule, id=rule_id)
    rules = list(FirewallRule.objects.order_by('priority'))
    print(rules)
    print(rule)
    current_order = rule.priority
    index = rules.index(rule)
   # (variable) rules: BaseManager[FirewallRule]

    if direction == 'up' and index > 0:
        # Swap priority with the rule above
        rule_above = rules[index - 1]
        rule.priority, rule_above.priority = rule_above.priority, current_order
        rule.save()
        rule_above.save()
    elif direction == 'down' and index < len(rules) - 1:
        # Swap order with the rule below
        rule_below = rules[index + 1]
        rule.priority, rule_below.priority = rule_below.priority, current_order
        rule.save()
        rule_below.save()

    return redirect('firewall_rules')
