from django.contrib import admin

from CvePatcherApp.models import Sponsor, User, Cve, Bounty, UserRegisteredBounty, SponsorPoint

# Register your models here.


@admin.register(Cve)
class CveAdmin(admin.ModelAdmin):
    list_display = ['Cve_Id', 'Name', 'Cvss3_Severity', 'Category', 'Fix_Type', 'In_Kev']
    list_filter = ['Category', 'Fix_Type', 'Cvss3_Severity', 'In_Kev']
    search_fields = ['Cve_Id', 'Name', 'Description']


@admin.register(Bounty)
class BountyAdmin(admin.ModelAdmin):
    list_display = ['Bounty_Id', 'Cve_Id', 'Type', 'Title', 'Value', 'Due_Date', 'Sponsor_Id']
    list_filter = ['Type']
    search_fields = ['Cve_Id__Cve_Id', 'Title']
    raw_id_fields = ['Cve_Id']


@admin.register(UserRegisteredBounty)
class UserRegisteredBountyAdmin(admin.ModelAdmin):
    list_display = ['Bounty_Id', 'User_Id', 'Is_Completed', 'Points_Earned', 'Registered_At']
    list_filter = ['Is_Completed']
    raw_id_fields = ['Bounty_Id']


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ['User_Id', 'Name', 'Email', 'Earned_Points']
    exclude = ['Password']


@admin.register(Sponsor)
class SponsorAdmin(admin.ModelAdmin):
    list_display = ['Sponsor_Id', 'Name', 'Email']
    exclude = ['Password']


admin.site.register(SponsorPoint)
