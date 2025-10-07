from django.shortcuts import render

# Create your views here.
from .models import UserRegistration
from .serializers import UserRegistrationSerializer
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status

@api_view(['POST'])
def register_user(request):
    serializer = UserRegistrationSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
def list_users(request):
    users = UserRegistration.objects.all()
    serializer = UserRegistrationSerializer(users, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)