# shortener/views.py
from django.views.decorators.csrf import csrf_exempt
from datetime import timedelta
from django.utils import timezone
from django.http import JsonResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from .models import ShortenedURL, AccessLog
import hashlib
import re
import json
from django.contrib.auth.hashers import make_password, check_password

def validate_url(url):
    # Regex to match well-formed URLs with the added protocol
    regex = re.compile(r'^(?:http|ftp)s?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+$')
    return re.match(regex, url) is not None

@csrf_exempt
def shorten_url(request):
    try:
        if request.method != "POST":
            return JsonResponse({"error": "Invalid HTTP method. Use POST."}, status=405)

        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON payload."}, status=400)

        if not isinstance(data, dict):
            return JsonResponse({"error": "Expected a JSON object."}, status=400)

        expected_keys = {"url": str, "expiry": (int, float), "password": str}
        for key in data.keys():
            if key not in expected_keys:
                return JsonResponse({"error": f"Unexpected key '{key}' in payload."}, status=400)
            if not isinstance(data[key], expected_keys[key]) and data[key] is not None:
                return JsonResponse({"error": f"The '{key}' key must be of type {expected_keys[key].__name__}."}, status=400)

        if 'url' not in data:
            return JsonResponse({"error": "The 'url' key is required."}, status=400)

        original_url = data["url"]
        expiry_hours = data.get("expiry", 24)
        password = data.get("password")

        if not validate_url(original_url):
            return JsonResponse({"error": "Invalid URL format."}, status=400)

        if password:
            hashed_password = make_password(password)
        else:
            hashed_password = None

        hash_object = hashlib.md5(original_url.encode())
        hash_string = hash_object.hexdigest()[:6]
        shortened_url_obj, created = ShortenedURL.objects.get_or_create(
            original_url=original_url,
            defaults={
                "shortened_url": hash_string,
                "expires_at": timezone.now() + timedelta(hours=expiry_hours),
                "password": hashed_password
            }
        )

        if not created:
            shortened_url_obj.expires_at = timezone.now() + timedelta(hours=expiry_hours)
            shortened_url_obj.password = hashed_password
            shortened_url_obj.save()

        return JsonResponse({
            "shortened_url": f"https://short.ly/{shortened_url_obj.shortened_url}",
            "expiry": shortened_url_obj.expires_at
        })

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)




def redirect_url(request, short_url):
    try:
        shortened_url_obj = get_object_or_404(ShortenedURL, shortened_url=short_url)

        if shortened_url_obj.is_expired():
            return JsonResponse({"error": "This URL has expired."}, status=404)

        # Add http:// to original URL if it doesn't have a scheme
        original_url = shortened_url_obj.original_url
        if not re.match(r'^(?:http|https)://', original_url):
            original_url = 'http://' + original_url

        password = request.GET.get('password')
        if shortened_url_obj.password:
            if not password or not check_password(password, shortened_url_obj.password):
                return JsonResponse({"error": "Invalid password."}, status=403)

        shortened_url_obj.access_count += 1
        shortened_url_obj.save()

        AccessLog.objects.create(shortened_url=shortened_url_obj, ip_address=request.META.get('REMOTE_ADDR'))

        return HttpResponseRedirect(original_url)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)




def url_analytics(request, short_url):
    try:
        shortened_url_obj = get_object_or_404(ShortenedURL, shortened_url=short_url)

        if shortened_url_obj.is_expired():
            return JsonResponse({"error": "This URL has expired."}, status=404)

        access_logs = AccessLog.objects.filter(shortened_url=shortened_url_obj)

        return JsonResponse({
            "original_url": shortened_url_obj.original_url,
            "access_count": shortened_url_obj.access_count,
            "logs": [{
                "timestamp": log.timestamp,
                "ip_address": log.ip_address
            } for log in access_logs]
        })
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)