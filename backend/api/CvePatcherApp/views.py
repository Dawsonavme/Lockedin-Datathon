from django.core import signing
from django.core.files.storage import default_storage
from django.db import transaction
from django.db.models import F, OuterRef, Q, Subquery, Sum
from django.db.models.functions import Coalesce
from django.views.decorators.csrf import csrf_exempt
from rest_framework.parsers import JSONParser
from django.http.response import JsonResponse
from django.utils import timezone

from CvePatcherApp import challenges, explain
from CvePatcherApp.models import Sponsor, User, Bounty, UserRegisteredBounty, SponsorPoint
from CvePatcherApp.serializers import (
    SponsorSerializer, UserSerializer, BountySerializer,
    UserRegisteredBountySerializer, SponsorPointSerializer,
    BountyCardSerializer, RegistrationCardSerializer,
)

# Create your views here.


def not_found(what):
    return JsonResponse({'detail': f'{what} not found'}, status=404)


def failed(message, serializer):
    return JsonResponse({'detail': message, 'errors': serializer.errors}, status=400)


@csrf_exempt
def sponsorApi(request, id=0):
    if request.method == 'GET':
        if id:
            sponsor = Sponsor.objects.filter(Sponsor_Id=id).first()
            return JsonResponse(SponsorSerializer(sponsor).data) if sponsor else not_found('Sponsor')
        sponsors = Sponsor.objects.all()
        sponsors_serializer = SponsorSerializer(sponsors, many=True)
        return JsonResponse(sponsors_serializer.data, safe=False)
    elif request.method == 'POST':
        sponsor_data = JSONParser().parse(request)
        sponsors_serializer = SponsorSerializer(data=sponsor_data)
        if sponsors_serializer.is_valid():
            sponsors_serializer.save()
            return JsonResponse("Added Successfully", safe=False)
        return failed("Failed to Add", sponsors_serializer)
    elif request.method == 'PUT':
        sponsor_data = JSONParser().parse(request)
        sponsor = Sponsor.objects.filter(Sponsor_Id=sponsor_data.get('Sponsor_Id')).first()
        if not sponsor:
            return not_found('Sponsor')
        sponsors_serializer = SponsorSerializer(sponsor, data=sponsor_data, partial=True)
        if sponsors_serializer.is_valid():
            sponsors_serializer.save()
            return JsonResponse("Update Successfully", safe=False)
        return failed("Failed to Update", sponsors_serializer)
    elif request.method == 'DELETE':
        deleted, _ = Sponsor.objects.filter(Sponsor_Id=id).delete()
        return JsonResponse("Deleted successfully", safe=False) if deleted else not_found('Sponsor')


@csrf_exempt
def userApi(request, id=0):
    if request.method == 'GET':
        if id:
            user = User.objects.filter(User_Id=id).first()
            return JsonResponse(UserSerializer(user).data) if user else not_found('User')
        users = User.objects.all()
        users_serializer = UserSerializer(users, many=True)
        return JsonResponse(users_serializer.data, safe=False)
    elif request.method == 'POST':
        user_data = JSONParser().parse(request)
        users_serializer = UserSerializer(data=user_data)
        if users_serializer.is_valid():
            users_serializer.save()
            return JsonResponse("Added Successfully", safe=False)
        return failed("Failed to Add", users_serializer)
    elif request.method == 'PUT':
        user_data = JSONParser().parse(request)
        user = User.objects.filter(User_Id=user_data.get('User_Id')).first()
        if not user:
            return not_found('User')
        users_serializer = UserSerializer(user, data=user_data, partial=True)
        if users_serializer.is_valid():
            users_serializer.save()
            return JsonResponse("Update Successfully", safe=False)
        return failed("Failed to Update", users_serializer)
    elif request.method == 'DELETE':
        deleted, _ = User.objects.filter(User_Id=id).delete()
        return JsonResponse("Deleted successfully", safe=False) if deleted else not_found('User')


@csrf_exempt
def bountyApi(request, id=0):
    if request.method == 'GET':
        if id:
            bounty = Bounty.objects.filter(Bounty_Id=id).first()
            return JsonResponse(BountySerializer(bounty).data) if bounty else not_found('Bounty')
        # There are ~240k open bounties, so the full list is paged: ?page=2 (100 per page).
        # The game uses /board, which adds filters and CVE details.
        page = max(int(request.GET.get('page', 1) or 1), 1)
        bounties = Bounty.objects.order_by('Bounty_Id')[(page - 1) * 100:page * 100]
        bounties_serializer = BountySerializer(bounties, many=True)
        return JsonResponse(bounties_serializer.data, safe=False)
    elif request.method == 'POST':
        bounty_data = JSONParser().parse(request)
        bounties_serializer = BountySerializer(data=bounty_data)
        if bounties_serializer.is_valid():
            bounties_serializer.save()
            return JsonResponse("Added Successfully", safe=False)
        return failed("Failed to Add", bounties_serializer)
    elif request.method == 'PUT':
        bounty_data = JSONParser().parse(request)
        bounty = Bounty.objects.filter(Bounty_Id=bounty_data.get('Bounty_Id')).first()
        if not bounty:
            return not_found('Bounty')
        bounties_serializer = BountySerializer(bounty, data=bounty_data, partial=True)
        if bounties_serializer.is_valid():
            bounties_serializer.save()
            return JsonResponse("Update Successfully", safe=False)
        return failed("Failed to Update", bounties_serializer)
    elif request.method == 'DELETE':
        deleted, _ = Bounty.objects.filter(Bounty_Id=id).delete()
        return JsonResponse("Deleted successfully", safe=False) if deleted else not_found('Bounty')


@csrf_exempt
def userRegisteredBountyApi(request, id=0):
    if request.method == 'GET':
        registrations = UserRegisteredBounty.objects.all()
        if id:  # id is a User_Id: that user's registrations
            registrations = registrations.filter(User_Id=id)
        registrations_serializer = UserRegisteredBountySerializer(registrations, many=True)
        return JsonResponse(registrations_serializer.data, safe=False)
    elif request.method == 'POST':
        registration_data = JSONParser().parse(request)
        registrations_serializer = UserRegisteredBountySerializer(data=registration_data)
        if registrations_serializer.is_valid():
            registrations_serializer.save()
            return JsonResponse("Added Successfully", safe=False)
        return failed("Failed to Add", registrations_serializer)
    elif request.method == 'PUT':
        registration_data = JSONParser().parse(request)
        # Composite key lookup: need both User_Id and Bounty_Id
        registration = UserRegisteredBounty.objects.filter(
            User_Id=registration_data.get('User_Id'),
            Bounty_Id=registration_data.get('Bounty_Id')
        ).first()
        if not registration:
            return not_found('Registration')
        registrations_serializer = UserRegisteredBountySerializer(registration, data=registration_data, partial=True)
        if registrations_serializer.is_valid():
            registrations_serializer.save()
            return JsonResponse("Update Successfully", safe=False)
        return failed("Failed to Update", registrations_serializer)
    elif request.method == 'DELETE':
        # For composite keys, both IDs must be passed (id here is treated as User_Id,
        # so prefer passing both via query params for reliability)
        user_id = request.GET.get('User_Id', id)
        bounty_id = request.GET.get('Bounty_Id')
        deleted, _ = UserRegisteredBounty.objects.filter(User_Id=user_id, Bounty_Id=bounty_id).delete()
        return JsonResponse("Deleted successfully", safe=False) if deleted else not_found('Registration')


@csrf_exempt
def sponsorPointApi(request, id=0):
    if request.method == 'GET':
        sponsor_points = SponsorPoint.objects.all()
        if id:  # id is a Bounty_Id: the points sponsors put on that bounty
            sponsor_points = sponsor_points.filter(Bounty_Id=id)
        sponsor_points_serializer = SponsorPointSerializer(sponsor_points, many=True)
        return JsonResponse(sponsor_points_serializer.data, safe=False)
    elif request.method == 'POST':
        sponsor_point_data = JSONParser().parse(request)
        sponsor_points_serializer = SponsorPointSerializer(data=sponsor_point_data)
        if sponsor_points_serializer.is_valid():
            sponsor_points_serializer.save()
            return JsonResponse("Added Successfully", safe=False)
        return failed("Failed to Add", sponsor_points_serializer)
    elif request.method == 'PUT':
        sponsor_point_data = JSONParser().parse(request)
        # Composite key lookup: need both Sponsor_Id and Bounty_Id
        sponsor_point = SponsorPoint.objects.filter(
            Sponsor_Id=sponsor_point_data.get('Sponsor_Id'),
            Bounty_Id=sponsor_point_data.get('Bounty_Id')
        ).first()
        if not sponsor_point:
            return not_found('Sponsor points')
        sponsor_points_serializer = SponsorPointSerializer(sponsor_point, data=sponsor_point_data, partial=True)
        if sponsor_points_serializer.is_valid():
            sponsor_points_serializer.save()
            return JsonResponse("Update Successfully", safe=False)
        return failed("Failed to Update", sponsor_points_serializer)
    elif request.method == 'DELETE':
        # For composite keys, both IDs must be passed
        sponsor_id = request.GET.get('Sponsor_Id', id)
        bounty_id = request.GET.get('Bounty_Id')
        deleted, _ = SponsorPoint.objects.filter(Sponsor_Id=sponsor_id, Bounty_Id=bounty_id).delete()
        return JsonResponse("Deleted successfully", safe=False) if deleted else not_found('Sponsor points')


@csrf_exempt
def SaveFile(request):
    file = request.FILES['file']
    file_name = default_storage.save(file.name, file)
    return JsonResponse(file_name, safe=False)


# ---------------------------------------------------------------------------
# Game: sign in, bounty board, accepting and completing bounties, challenges
# ---------------------------------------------------------------------------

TOKEN_SALT = 'cve-catcher-login'
TOKEN_MAX_AGE = 60 * 60 * 24 * 30  # 30 days
BOARD_PAGE_SIZE = 20
BOARD_SORTS = {'Value', 'Urgency', 'Difficulty', 'Rarity', 'Date_Created', 'Due_Date'}


def make_token(account):
    role = 'sponsor' if isinstance(account, Sponsor) else 'user'
    return signing.dumps({'role': role, 'id': account.pk}, salt=TOKEN_SALT)


def signed_in(request):
    """The User or Sponsor from the 'Authorization: Token <token>' header, or None."""
    header = request.headers.get('Authorization', '')
    if not header.startswith('Token '):
        return None
    try:
        data = signing.loads(header[6:], salt=TOKEN_SALT, max_age=TOKEN_MAX_AGE)
    except signing.BadSignature:
        return None
    model = Sponsor if data['role'] == 'sponsor' else User
    return model.objects.filter(pk=data['id']).first()


def error(message, status=400):
    return JsonResponse({'detail': message}, status=status)


def board_bounties():
    """Bounties with their CVE, sponsor and Added (sponsor top-ups) in one query."""
    added = (
        SponsorPoint.objects.filter(Bounty_Id=OuterRef('pk'))
        .values('Bounty_Id').annotate(total=Sum('Added_Points')).values('total')
    )
    return (
        Bounty.objects.select_related('Cve_Id', 'Sponsor_Id')
        .annotate(Added=Coalesce(Subquery(added), 0))
    )


@csrf_exempt
def signupApi(request):
    """POST {Name, Email, Password, Role: "user" | "sponsor"} -> {Token, Role}"""
    if request.method != 'POST':
        return error('POST only', 405)
    data = JSONParser().parse(request)
    role = data.pop('Role', 'user')
    serializer_class = SponsorSerializer if role == 'sponsor' else UserSerializer
    serializer = serializer_class(data=data)
    if not serializer.is_valid():
        return failed('Failed to sign up', serializer)
    if len(data.get('Password', '')) < 8:
        return error('Password must be at least 8 characters')
    account = serializer.save()
    return JsonResponse({'Token': make_token(account), 'Role': role}, status=201)


@csrf_exempt
def loginApi(request):
    """POST {Email, Password} -> {Token, Role}"""
    if request.method != 'POST':
        return error('POST only', 405)
    data = JSONParser().parse(request)
    for account in [User.objects.filter(Email=data.get('Email')).first(),
                    Sponsor.objects.filter(Email=data.get('Email')).first()]:
        if account and account.check_password(data.get('Password', '')):
            role = 'sponsor' if isinstance(account, Sponsor) else 'user'
            return JsonResponse({'Token': make_token(account), 'Role': role})
    return error('Wrong email or password', 401)


def meApi(request):
    account = signed_in(request)
    if not account:
        return error('Sign in first', 401)
    if isinstance(account, Sponsor):
        return JsonResponse({'Role': 'sponsor', **SponsorSerializer(account).data})
    registrations = (
        UserRegisteredBounty.objects.filter(User_Id=account)
        .select_related('Bounty_Id__Cve_Id', 'Bounty_Id__Sponsor_Id')
        .order_by('-Registered_At')
    )
    return JsonResponse({
        'Role': 'user',
        **UserSerializer(account).data,
        'Registrations': RegistrationCardSerializer(registrations, many=True).data,
    })


def boardApi(request, id=0):
    """The bounty board.

    /board/<id>: one bounty. /board: a page of bounties, filtered by ?Type= (default open),
    Category=, Fix_Type=, Severity=, Search= (CVE ID or description), sorted by
    ?Sort= (Value, Urgency, Difficulty, Rarity, Date_Created, Due_Date; prefix - for
    descending, default -Value), and paged by ?Page=.
    """
    if id:
        bounty = board_bounties().filter(Bounty_Id=id).first()
        return JsonResponse(BountyCardSerializer(bounty).data) if bounty else not_found('Bounty')

    params = request.GET
    bounties = board_bounties().filter(Type=params.get('Type', Bounty.OPEN))
    if params.get('Category'):
        bounties = bounties.filter(Cve_Id__Category=params['Category'])
    if params.get('Fix_Type'):
        bounties = bounties.filter(Cve_Id__Fix_Type=params['Fix_Type'])
    if params.get('Severity'):
        bounties = bounties.filter(Cve_Id__Cvss3_Severity=params['Severity'].upper())
    if params.get('Search'):
        term = params['Search']
        bounties = bounties.filter(Q(Cve_Id__Cve_Id__icontains=term) | Q(Cve_Id__Description__icontains=term))
    sort = params.get('Sort', '-Value')
    if sort.lstrip('-') not in BOARD_SORTS:
        sort = '-Value'
    bounties = bounties.order_by(sort, 'Bounty_Id')

    try:
        page = max(int(params.get('Page', 1)), 1)
    except ValueError:
        page = 1
    count = bounties.count()
    start = (page - 1) * BOARD_PAGE_SIZE
    return JsonResponse({
        'Count': count,
        'Page': page,
        'Has_Next': start + BOARD_PAGE_SIZE < count,
        'Results': BountyCardSerializer(bounties[start:start + BOARD_PAGE_SIZE], many=True).data,
    })


def explainApi(request, id):
    """GET: Granite's plain-language explanation of the bounty's CVE -> {Cve_Id, Explanation}"""
    bounty = Bounty.objects.select_related('Cve_Id').filter(Bounty_Id=id).first()
    if not bounty:
        return not_found('Bounty')
    try:
        text = explain.explanation(bounty.Cve_Id)
    except explain.GraniteUnavailable:
        return error("Granite isn't available right now. Try again in a minute.", 503)
    return JsonResponse({'Cve_Id': bounty.Cve_Id.Cve_Id, 'Explanation': text})


@csrf_exempt
def registerApi(request, id):
    """POST: the signed-in user accepts a bounty."""
    if request.method != 'POST':
        return error('POST only', 405)
    user = signed_in(request)
    if not isinstance(user, User):
        return error('Only hunters can accept bounties', 403)
    bounty = Bounty.objects.filter(Bounty_Id=id).first()
    if not bounty:
        return not_found('Bounty')
    if bounty.Due_Date and bounty.Due_Date < timezone.localdate():
        return error('This bounty has expired')
    registration, created = UserRegisteredBounty.objects.get_or_create(User_Id=user, Bounty_Id=bounty)
    return JsonResponse(UserRegisteredBountySerializer(registration).data, status=201 if created else 200)


@csrf_exempt
def completeApi(request, id):
    """POST: mark an accepted bounty as fixed and award its points.

    The points are locked in now, so later re-scoring does not change them.
    NOTE: this trusts the user; nothing checks yet that the fix is real.
    """
    if request.method != 'POST':
        return error('POST only', 405)
    user = signed_in(request)
    if not isinstance(user, User):
        return error('Only hunters can complete bounties', 403)
    with transaction.atomic():
        registration = (
            UserRegisteredBounty.objects.select_for_update().select_related('Bounty_Id')
            .filter(User_Id=user, Bounty_Id=id).first()
        )
        if not registration:
            return error('Accept the bounty first', 404)
        bounty = registration.Bounty_Id
        if registration.Is_Completed:
            return error('Already completed')
        if bounty.Due_Date and bounty.Due_Date < timezone.localdate():
            return error('This bounty has expired')
        # Open, daily and weekly bounties can share a CVE; points only count once per CVE
        if UserRegisteredBounty.objects.filter(User_Id=user, Is_Completed=True,
                                               Bounty_Id__Cve_Id=bounty.Cve_Id_id).exists():
            return error('You already earned points for this CVE')

        registration.Is_Completed = True
        registration.Completed_At = timezone.now()
        registration.Points_Earned = bounty.total_value()
        registration.save()
        User.objects.filter(pk=user.pk).update(Earned_Points=F('Earned_Points') + registration.Points_Earned)
    return JsonResponse(UserRegisteredBountySerializer(registration).data)


@csrf_exempt
def addPointsApi(request, id):
    """POST {Points}: the signed-in sponsor adds points to a bounty."""
    if request.method != 'POST':
        return error('POST only', 405)
    sponsor = signed_in(request)
    if not isinstance(sponsor, Sponsor):
        return error('Only sponsors can add points', 403)
    bounty = Bounty.objects.filter(Bounty_Id=id).first()
    if not bounty:
        return not_found('Bounty')
    try:
        points = int(JSONParser().parse(request).get('Points', 0))
    except (TypeError, ValueError):
        points = 0
    if points <= 0:
        return error('Points must be a positive whole number')
    # One SPONSOR_POINTS row per sponsor and bounty, so adding again tops it up
    contribution, created = SponsorPoint.objects.get_or_create(
        Sponsor_Id=sponsor, Bounty_Id=bounty, defaults={'Added_Points': points}
    )
    if not created:
        SponsorPoint.objects.filter(pk=contribution.pk).update(Added_Points=F('Added_Points') + points)
    return JsonResponse(BountyCardSerializer(board_bounties().get(Bounty_Id=id)).data)


def challengesApi(request):
    today = timezone.localdate()
    daily = challenges.daily(today)
    weekly = challenges.weekly(today)
    ids = [b.pk for b in weekly] + ([daily.pk] if daily else [])
    by_id = {b.pk: b for b in board_bounties().filter(Bounty_Id__in=ids)}
    return JsonResponse({
        'Daily': BountyCardSerializer(by_id[daily.pk]).data if daily else None,
        'Weekly': {
            'Title': weekly[0].Title if weekly else None,
            'Due_Date': weekly[0].Due_Date if weekly else None,
            'Bounties': BountyCardSerializer([by_id[b.pk] for b in weekly], many=True).data,
        },
    })


def leaderboardApi(request):
    users = User.objects.order_by('-Earned_Points', 'Name')[:50]
    return JsonResponse([{'User_Id': u.User_Id, 'Name': u.Name, 'Earned_Points': u.Earned_Points} for u in users],
                        safe=False)
