from rest_framework import serializers
from CvePatcherApp.models import Sponsor, User, Cve, Bounty, UserRegisteredBounty, SponsorPoint


class HashedPasswordMixin:
    """Password is accepted on create/update, stored hashed, and never sent back."""

    def create(self, validated_data):
        raw = validated_data.pop('Password')
        account = self.Meta.model(**validated_data)
        account.set_password(raw)
        account.save()
        return account

    def update(self, instance, validated_data):
        raw = validated_data.pop('Password', None)
        instance = super().update(instance, validated_data)
        if raw:
            instance.set_password(raw)
            instance.save()
        return instance


class SponsorSerializer(HashedPasswordMixin, serializers.ModelSerializer):
    class Meta:
        model = Sponsor
        fields = ('Sponsor_Id', 'Name', 'Email', 'Password')
        extra_kwargs = {'Password': {'write_only': True}}

class UserSerializer(HashedPasswordMixin, serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('User_Id', 'Name', 'Email', 'Password', 'Earned_Points')
        # Points only change by completing bounties
        extra_kwargs = {'Password': {'write_only': True}, 'Earned_Points': {'read_only': True}}

class CveSerializer(serializers.ModelSerializer):
    class Meta:
        model = Cve
        fields = '__all__'

class BountySerializer(serializers.ModelSerializer):
    class Meta:
        model = Bounty
        fields = ('Bounty_Id', 'Cve_Id', 'Sponsor_Id', 'Value', 'Date_Created', 'Due_Date', 'Type', 'Title')

class UserRegisteredBountySerializer(serializers.ModelSerializer):
    class Meta:
        model = UserRegisteredBounty
        fields = ('User_Id', 'Bounty_Id', 'Is_Completed', 'Points_Earned')

class SponsorPointSerializer(serializers.ModelSerializer):
    class Meta:
        model = SponsorPoint
        fields = ('Sponsor_Id', 'Bounty_Id', 'Added_Points')


# Game serializers: what the bounty board and bounty pages show

class BountyCardSerializer(serializers.ModelSerializer):
    """A bounty with its CVE, sponsor name, total reward and how the reward was worked out."""
    Cve = CveSerializer(source='Cve_Id', read_only=True)
    Sponsor = serializers.CharField(source='Sponsor_Id.Name', default=None, read_only=True)
    Total_Value = serializers.SerializerMethodField()

    class Meta:
        model = Bounty
        fields = ('Bounty_Id', 'Cve', 'Type', 'Title', 'Value', 'Total_Value', 'Date_Created', 'Due_Date',
                  'Sponsor', 'Severity', 'Urgency', 'Difficulty', 'Rarity', 'Impact_Source')

    def get_Total_Value(self, bounty):
        # Views annotate Added to avoid one query per bounty
        added = getattr(bounty, 'Added', None)
        return bounty.Value + added if added is not None else bounty.total_value()

class RegistrationCardSerializer(serializers.ModelSerializer):
    Bounty = BountyCardSerializer(source='Bounty_Id', read_only=True)

    class Meta:
        model = UserRegisteredBounty
        fields = ('Bounty', 'Is_Completed', 'Points_Earned', 'Registered_At', 'Completed_At')
