# True negative: explicit field assignment (safe)
from django.http import JsonResponse

def create_user(request):
    # ok: ez-django-mass-assignment
    User.objects.create(
        username=request.POST.get("username"),
        email=request.POST.get("email"),
    )
    return JsonResponse({"ok": True})
