# True negative: hardcoded header value (safe)
from django.http import HttpResponse

def set_language(request):
    # ok: ez-django-header-injection
    response = HttpResponse("OK")
    response["Content-Language"] = "en-US"
    return response
