from django.db import models

# Create your models here.

class Sponsor(models.Model):
    Sponsor_Id = models.AutoField(primary_key=True)
    Name = models.TextField()
    Email = models.TextField(unique=True)
    Password = models.TextField()

    class Meta:
        managed = True
        db_table = 'SPONSOR'

class User(models.Model):
    User_Id = models.AutoField(primary_key=True)
    Name = models.TextField()
    Email = models.TextField(unique=True)
    Password = models.TextField()
    Earned_Points = models.IntegerField(default=0)

    class Meta:
        managed = True
        db_table = 'USER'

class Bounty(models.Model):
    Bounty_Id = models.AutoField(primary_key=True)
    Cve_Id = models.IntegerField()
    Sponsor_Id = models.ForeignKey(Sponsor, models.DO_NOTHING, db_column='Sponsor_Id')
    Value = models.IntegerField()
    Date_Created = models.DateField()
    Due_Date = models.DateField()
    Type = models.TextField()

    class Meta:
        managed = True
        db_table = 'BOUNTY'

class UserRegisteredBounty(models.Model):
    User_Id = models.ForeignKey(User, models.DO_NOTHING, db_column='User_Id')
    Bounty_Id = models.ForeignKey(Bounty, models.DO_NOTHING, db_column='Bounty_Id')
    Is_Completed = models.BooleanField(default=False)
    Points_Earned = models.IntegerField(default=0)

    class Meta:
        managed = True
        db_table = 'USER_REGISTERED_BOUNTIES'
        # Django doesn't natively support composite Primary Keys in the ORM.
        # We use unique_together to mimic the constraint.
        unique_together = (('User_Id', 'Bounty_Id'),)

class SponsorPoint(models.Model):
    Sponsor_Id = models.ForeignKey(Sponsor, models.DO_NOTHING, db_column='Sponsor_Id')
    Bounty_Id = models.ForeignKey(Bounty, models.DO_NOTHING, db_column='Bounty_Id')
    Added_Points = models.IntegerField()

    class Meta:
        managed = True
        db_table = 'SPONSOR_POINTS'
        unique_together = (('Sponsor_Id', 'Bounty_Id'),)