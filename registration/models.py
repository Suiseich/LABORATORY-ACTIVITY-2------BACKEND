from django.db import models

# Create your models here.

class UserRegistration(models.Model):
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    email = models.EmailField(max_length=100)
    password = models.CharField(max_length=150)
    date_registration = models.DateField(auto_now_add=True)
    gender = models.CharField(max_length=16)

    def __str__(self):
        return f"{self.first_name}{self.last_name}"