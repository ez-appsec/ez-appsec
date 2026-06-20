# True negative: lookup scoped to current user (safe)
from django.http import JsonResponse

def get_invoice(request):
    # ok: ez-django-idor-get-parameter
    invoice_id = request.GET.get("id")
    invoice = Invoice.objects.filter(user=request.user).get(pk=invoice_id)
    return JsonResponse({"total": invoice.total})
