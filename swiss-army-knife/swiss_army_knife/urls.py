from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    # Include toolkit URLs at the root
    path('', include('toolkit.urls')),
]