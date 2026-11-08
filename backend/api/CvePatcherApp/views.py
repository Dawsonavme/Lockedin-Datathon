from django.shortcuts import render

# Create your views here.
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from rest_framework.parsers import JSONParser
from django.http.response import JsonResponse

from CvePatcherApp.models import Sponsor, User, Bounty, UserRegisteredBounty, SponsorPoint
from CvePatcherApp.serializers import (
    SponsorSerializer, UserSerializer, BountySerializer,
    UserRegisteredBountySerializer, SponsorPointSerializer
)

# Create your views here.


@csrf_exempt
def sponsorApi(request, id=0):
    if request.method == 'GET':
        sponsors = Sponsor.objects.all()
        sponsors_serializer = SponsorSerializer(sponsors, many=True)
        return JsonResponse(sponsors_serializer.data, safe=False)
    elif request.method == 'POST':
        sponsor_data = JSONParser().parse(request)
        sponsors_serializer = SponsorSerializer(data=sponsor_data)
        if sponsors_serializer.is_valid():
            sponsors_serializer.save()
            return JsonResponse("Added Successfully", safe=False)
        return JsonResponse("Failed to Add", safe=False)
    elif request.method == 'PUT':
        sponsor_data = JSONParser().parse(request)
        sponsor = Sponsor.objects.get(Sponsor_id=sponsor_data['Sponsor_id'])
        sponsors_serializer = SponsorSerializer(sponsor, data=sponsor_data)
        if sponsors_serializer.is_valid():
            sponsors_serializer.save()
            return JsonResponse("Update Successfully", safe=False)
        return JsonResponse("Failed to Update", safe=False)
    elif request.method == 'DELETE':
        sponsor = Sponsor.objects.get(Sponsor_id=id)
        sponsor.delete()
        return JsonResponse("Deleted successfully", safe=False)


@csrf_exempt
def userApi(request, id=0):
    if request.method == 'GET':
        users = User.objects.all()
        users_serializer = UserSerializer(users, many=True)
        return JsonResponse(users_serializer.data, safe=False)
    elif request.method == 'POST':
        user_data = JSONParser().parse(request)
        users_serializer = UserSerializer(data=user_data)
        if users_serializer.is_valid():
            users_serializer.save()
            return JsonResponse("Added Successfully", safe=False)
        return JsonResponse("Failed to Add", safe=False)
    elif request.method == 'PUT':
        user_data = JSONParser().parse(request)
        user = User.objects.get(User_id=user_data['User_id'])
        users_serializer = UserSerializer(user, data=user_data)
        if users_serializer.is_valid():
            users_serializer.save()
            return JsonResponse("Update Successfully", safe=False)
        return JsonResponse("Failed to Update", safe=False)
    elif request.method == 'DELETE':
        user = User.objects.get(User_id=id)
        user.delete()
        return JsonResponse("Deleted successfully", safe=False)


@csrf_exempt
def bountyApi(request, id=0):
    if request.method == 'GET':
        bounties = Bounty.objects.all()
        bounties_serializer = BountySerializer(bounties, many=True)
        return JsonResponse(bounties_serializer.data, safe=False)
    elif request.method == 'POST':
        bounty_data = JSONParser().parse(request)
        bounties_serializer = BountySerializer(data=bounty_data)
        if bounties_serializer.is_valid():
            bounties_serializer.save()
            return JsonResponse("Added Successfully", safe=False)
        return JsonResponse("Failed to Add", safe=False)
    elif request.method == 'PUT':
        bounty_data = JSONParser().parse(request)
        bounty = Bounty.objects.get(Id=bounty_data['Id'])
        bounties_serializer = BountySerializer(bounty, data=bounty_data)
        if bounties_serializer.is_valid():
            bounties_serializer.save()
            return JsonResponse("Update Successfully", safe=False)
        return JsonResponse("Failed to Update", safe=False)
    elif request.method == 'DELETE':
        bounty = Bounty.objects.get(Id=id)
        bounty.delete()
        return JsonResponse("Deleted successfully", safe=False)


@csrf_exempt
def userRegisteredBountyApi(request, id=0):
    if request.method == 'GET':
        registrations = UserRegisteredBounty.objects.all()
        registrations_serializer = UserRegisteredBountySerializer(registrations, many=True)
        return JsonResponse(registrations_serializer.data, safe=False)
    elif request.method == 'POST':
        registration_data = JSONParser().parse(request)
        registrations_serializer = UserRegisteredBountySerializer(data=registration_data)
        if registrations_serializer.is_valid():
            registrations_serializer.save()
            return JsonResponse("Added Successfully", safe=False)
        return JsonResponse("Failed to Add", safe=False)
    elif request.method == 'PUT':
        registration_data = JSONParser().parse(request)
        # Composite key lookup: need both User_id and Bounty_id
        registration = UserRegisteredBounty.objects.get(
            User_id=registration_data['User_id'],
            Bounty_id=registration_data['Bounty_id']
        )
        registrations_serializer = UserRegisteredBountySerializer(registration, data=registration_data)
        if registrations_serializer.is_valid():
            registrations_serializer.save()
            return JsonResponse("Update Successfully", safe=False)
        return JsonResponse("Failed to Update", safe=False)
    elif request.method == 'DELETE':
        # For composite keys, both IDs must be passed (id here is treated as User_id,
        # so prefer passing both via query params for reliability)
        user_id = request.GET.get('User_id', id)
        bounty_id = request.GET.get('Bounty_id')
        registration = UserRegisteredBounty.objects.get(User_id=user_id, Bounty_id=bounty_id)
        registration.delete()
        return JsonResponse("Deleted successfully", safe=False)


@csrf_exempt
def sponsorPointApi(request, id=0):
    if request.method == 'GET':
        sponsor_points = SponsorPoint.objects.all()
        sponsor_points_serializer = SponsorPointSerializer(sponsor_points, many=True)
        return JsonResponse(sponsor_points_serializer.data, safe=False)
    elif request.method == 'POST':
        sponsor_point_data = JSONParser().parse(request)
        sponsor_points_serializer = SponsorPointSerializer(data=sponsor_point_data)
        if sponsor_points_serializer.is_valid():
            sponsor_points_serializer.save()
            return JsonResponse("Added Successfully", safe=False)
        return JsonResponse("Failed to Add", safe=False)
    elif request.method == 'PUT':
        sponsor_point_data = JSONParser().parse(request)
        # Composite key lookup: need both Sponsor_id and Bounty_id
        sponsor_point = SponsorPoint.objects.get(
            Sponsor_id=sponsor_point_data['Sponsor_id'],
            Bounty_id=sponsor_point_data['Bounty_id']
        )
        sponsor_points_serializer = SponsorPointSerializer(sponsor_point, data=sponsor_point_data)
        if sponsor_points_serializer.is_valid():
            sponsor_points_serializer.save()
            return JsonResponse("Update Successfully", safe=False)
        return JsonResponse("Failed to Update", safe=False)
    elif request.method == 'DELETE':
        # For composite keys, both IDs must be passed
        sponsor_id = request.GET.get('Sponsor_id', id)
        bounty_id = request.GET.get('Bounty_id')
        sponsor_point = SponsorPoint.objects.get(Sponsor_id=sponsor_id, Bounty_id=bounty_id)
        sponsor_point.delete()
        return JsonResponse("Deleted successfully", safe=False)


@csrf_exempt
def SaveFile(request):
    file = request.FILES['file']
    file_name = default_storage.save(file.name, file)
    return JsonResponse(file_name, safe=False)