from django.db import models
import hashlib
from datetime import timedelta
from django.utils import timezone


class ShortenedURL(models.Model):
    original_url = models.URLField(unique=True)  # Stores the original URL
    shortened_url = models.CharField(max_length=10, unique=True)  # Stores the shortened URL
    created_at = models.DateTimeField(auto_now_add=True)  # Timestamp when the URL was created
    expires_at = models.DateTimeField()  # Expiration date for the shortened URL
    access_count = models.IntegerField(default=0)  # Number of times the shortened URL has been accessed
    password = models.CharField(max_length=255, blank=True, null=True)  # Optional password

    def is_expired(self):
        """Checks if the shortened URL has expired"""
        return timezone.now() > self.expires_at

    def generate_shortened_url(self):
        """Generates a shortened URL based on the original URL"""
        return hashlib.md5(self.original_url.encode()).hexdigest()[:6]  # First 6 chars of MD5 hash

    def save(self, *args, **kwargs):
        """Overrides the save method to generate the shortened URL if not provided and set the expiration time"""
        if not self.shortened_url:
            self.shortened_url = self.generate_shortened_url()
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(hours=24)  # Default expiration time is 24 hours
        super().save(*args, **kwargs)

    def __str__(self):
        """Returns the shortened URL as string representation"""
        return self.shortened_url


class AccessLog(models.Model):
    shortened_url = models.ForeignKey(ShortenedURL, on_delete=models.CASCADE)  # Link to the Shortened URL
    timestamp = models.DateTimeField(auto_now_add=True)  # Timestamp of when the shortened URL was accessed
    ip_address = models.GenericIPAddressField()  # IP address of the user accessing the URL

    def __str__(self):
        """Returns a string representation of the access log entry"""
        return f"{self.shortened_url.shortened_url} accessed from {self.ip_address} at {self.timestamp}"
