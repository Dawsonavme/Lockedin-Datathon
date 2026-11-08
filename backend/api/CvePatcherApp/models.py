from django.contrib.auth.hashers import check_password, make_password
from django.db import models
from django.db.models import Sum
from django.utils import timezone

# Create your models here.


class PasswordMixin:
    """Passwords are stored hashed. Call set_password() rather than assigning Password."""

    def set_password(self, raw):
        self.Password = make_password(raw)

    def check_password(self, raw):
        return check_password(raw, self.Password)


class Sponsor(PasswordMixin, models.Model):
    Sponsor_Id = models.AutoField(primary_key=True)
    Name = models.TextField()
    Email = models.TextField(unique=True)
    Password = models.TextField()  # hashed

    class Meta:
        managed = True
        db_table = 'SPONSOR'

    def __str__(self):
        return self.Name


class User(PasswordMixin, models.Model):
    User_Id = models.AutoField(primary_key=True)
    Name = models.TextField()
    Email = models.TextField(unique=True)
    Password = models.TextField()  # hashed
    Earned_Points = models.IntegerField(default=0)

    class Meta:
        managed = True
        db_table = 'USER'

    def __str__(self):
        return self.Name


class Cve(models.Model):
    """One vulnerability, loaded from the Bounty data pipeline (manage.py load_bounties)."""
    Cve_Id = models.CharField(max_length=32, primary_key=True)  # e.g. CVE-2024-3400
    Name = models.TextField(blank=True)  # CISA's name, for CVEs on the KEV list
    Description = models.TextField()
    Published = models.DateField(null=True, blank=True)
    Cvss3_Score = models.FloatField(null=True, blank=True)
    Cvss3_Severity = models.TextField(blank=True)
    Cwe_Id = models.TextField(blank=True)
    Cwe_Name = models.TextField(blank=True)
    # Labels from Granite (blank until the CVE has been labelled)
    Category = models.TextField(blank=True)  # injection, memory, access, other
    Fix_Type = models.TextField(blank=True)  # upgrade, code_change, config, unclear
    In_Kev = models.BooleanField(default=False)

    class Meta:
        managed = True
        db_table = 'CVE'

    def __str__(self):
        return self.Cve_Id


class Bounty(models.Model):
    # Type values
    OPEN = 'open'            # one per CVE, points from the scoring formula
    DAILY = 'daily'          # daily challenge
    WEEKLY = 'weekly'        # weekly challenge
    SPONSORED = 'sponsored'  # created by a sponsor

    Bounty_Id = models.AutoField(primary_key=True)
    Cve_Id = models.ForeignKey(Cve, models.CASCADE, db_column='Cve_Id', related_name='bounties')
    # Blank for bounties the system creates from the scoring data
    Sponsor_Id = models.ForeignKey(Sponsor, models.SET_NULL, db_column='Sponsor_Id', null=True, blank=True)
    Value = models.IntegerField()
    Date_Created = models.DateField(auto_now_add=True)
    Due_Date = models.DateField(null=True, blank=True)  # set for challenges
    Type = models.TextField(default=OPEN)
    Title = models.TextField(blank=True)  # e.g. "Memory Safety Week"
    # Why the bounty is worth what it is: Value = Severity x Urgency x Difficulty x Rarity
    Severity = models.FloatField(default=0)
    Urgency = models.FloatField(default=0)
    Difficulty = models.FloatField(default=0)
    Rarity = models.FloatField(default=0)
    Impact_Source = models.TextField(blank=True)  # nvd or granite

    class Meta:
        managed = True
        db_table = 'BOUNTY'
        constraints = [
            # One open bounty per CVE, so reloading the data updates it in place
            models.UniqueConstraint(fields=['Cve_Id'], condition=models.Q(Type='open'), name='one_open_bounty_per_cve'),
        ]
        indexes = [models.Index(fields=['Type', '-Value'])]

    def total_value(self):
        """Points a user gets for completing it: Value plus sponsor top-ups."""
        added = self.sponsorpoint_set.aggregate(total=Sum('Added_Points'))['total'] or 0
        return self.Value + added


class UserRegisteredBounty(models.Model):
    User_Id = models.ForeignKey(User, models.CASCADE, db_column='User_Id')
    Bounty_Id = models.ForeignKey(Bounty, models.CASCADE, db_column='Bounty_Id')
    Is_Completed = models.BooleanField(default=False)
    Points_Earned = models.IntegerField(default=0)  # locked in at completion
    Registered_At = models.DateTimeField(default=timezone.now)
    Completed_At = models.DateTimeField(null=True, blank=True)

    class Meta:
        managed = True
        db_table = 'USER_REGISTERED_BOUNTIES'
        # Django doesn't natively support composite Primary Keys in the ORM.
        # We use unique_together to mimic the constraint.
        unique_together = (('User_Id', 'Bounty_Id'),)


class SponsorPoint(models.Model):
    Sponsor_Id = models.ForeignKey(Sponsor, models.CASCADE, db_column='Sponsor_Id')
    Bounty_Id = models.ForeignKey(Bounty, models.CASCADE, db_column='Bounty_Id')
    Added_Points = models.IntegerField()

    class Meta:
        managed = True
        db_table = 'SPONSOR_POINTS'
        unique_together = (('Sponsor_Id', 'Bounty_Id'),)
