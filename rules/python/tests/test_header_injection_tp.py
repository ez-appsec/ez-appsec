# True positive: user input placed into response header
from django.http import HttpResponse

def set_language(request):
    # ruleid: ez-django-header-injection
    lang = request.GET.get("lang")
    response = HttpResponse("OK")
    response["Content-Language"] = lang
    return response
