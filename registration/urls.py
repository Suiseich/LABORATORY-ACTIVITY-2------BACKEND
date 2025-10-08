from django.urls import path
from . import views

urlpatterns = [
    path('api/register/', views.register_user, name='register_user'),
    path('api/users/', views.list_users, name='list_user'),
    path('api/users/<int:pk>/', views.user_detail, name='user_detail'),
]