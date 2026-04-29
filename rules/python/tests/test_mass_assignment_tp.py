# True positive: mass assignment via request.POST.dict()
from django.http import JsonResponse

def create_user(request):
    # ruleid: ez-django-mass-assignment
    User.objects.create(**request.POST.dict())
    return JsonResponse({"ok": True})
