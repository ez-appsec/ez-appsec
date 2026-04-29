# True positive: csrf_exempt on a state-changing view
from django.views.decorators.csrf import csrf_exempt

# ruleid: ez-django-csrf-exempt
@csrf_exempt
def transfer_funds(request):
    amount = request.POST.get("amount")
    return do_transfer(amount)
