from rest_framework import serializers
from CvePatcherApp.models import Sponsor, User, Bounty, UserRegisteredBounty, SponsorPoint

class SponsorSerializer(serializers.ModelSerializer):
    class Meta:
        model = Sponsor
        fields = ('Sponsor_Id', 'Name', 'Email', 'Password')

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('User_Id', 'Name', 'Email', 'Password', 'Earned_Points')

class BountySerializer(serializers.ModelSerializer):
    class Meta:
        model = Bounty
        fields = ('Bounty_Id', 'Cve_Id', 'Sponsor_Id', 'Value', 'Date_Created', 'Due_Date', 'Type')

class UserRegisteredBountySerializer(serializers.ModelSerializer):
    class Meta:
        model = UserRegisteredBounty
        fields = ('User_Id', 'Bounty_Id', 'Is_Completed', 'PointsEarned')

class SponsorPointSerializer(serializers.ModelSerializer):
    class Meta:
        model = SponsorPoint
        fields = ('Sponsor_Id', 'Bounty_Id', 'Added_Points')