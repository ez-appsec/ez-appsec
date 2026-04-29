# True negative: no csrf_exempt decorator (safe)
from django.http import JsonResponse

def transfer_funds(request):
    # ok: ez-django-csrf-exempt
    amount = request.POST.get("amount")
    return do_transfer(amount)
