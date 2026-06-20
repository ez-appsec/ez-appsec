# True positive: IDOR via direct object lookup without ownership check
from django.http import JsonResponse

def get_invoice(request):
    # ruleid: ez-django-idor-get-parameter
    invoice_id = request.GET.get("id")
    invoice = Invoice.objects.get(pk=invoice_id)
    return JsonResponse({"total": invoice.total})
