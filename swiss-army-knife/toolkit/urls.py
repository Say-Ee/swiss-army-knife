from django.urls import path
from . import views

urlpatterns = [
    path('hash-base64/', views.hash_base64_tool, name='hash_base64_tool'),
]
