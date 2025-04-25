# toolkit/urls.py
from django.urls import path
from . import views

urlpatterns = [
    # Map the root path of the app ('') to the new combined view
    path('', views.combined_toolkit_view, name='toolkit_home'),

    # You can keep old paths if needed for direct access or API,
    # but the primary UI will be the combined view.
    # path('hash-base64/', views.hash_base64_tool, name='hash_base64_tool'),
    # path('ip-geo-port-tool/', views.ip_geo_port_tool, name='ip_geo_port_tool'),
]