# True positive: pickle deserialization of user input
import pickle

def load_data(request):
    # ruleid: ez-django-insecure-deserialization
    data = request.body
    obj = pickle.loads(data)
    return obj
