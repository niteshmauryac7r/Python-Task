# url_shortener/urls.py

from django.contrib import admin
from django.urls import path, include  # Ensure `include` is imported

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('shortener.urls')),  # This line includes the shortener app's URLs
]
