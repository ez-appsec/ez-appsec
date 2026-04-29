# True negative: json.loads is safe
import json

def load_data(request):
    # ok: ez-django-insecure-deserialization
    data = request.body
    obj = json.loads(data)
    return obj
