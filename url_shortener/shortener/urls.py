# shortener/urls.py

from django.urls import path
from django.views.generic import TemplateView
from . import views  # Your custom views

urlpatterns = [
    path('shorten', views.shorten_url, name='shorten_url'),
    path('<str:short_url>', views.redirect_url, name='redirect_url'),
    path('analytics/<str:short_url>', views.url_analytics, name='url_analytics'),
]
