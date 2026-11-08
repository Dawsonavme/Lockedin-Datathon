"""Daily and weekly challenges, created the first time someone asks for them.

Daily:  one hot bounty a day, worth DAILY_BONUS x its open value, due the next day.
        Everyone gets the same pick, because the random choice is seeded by the date.
Weekly: WEEKLY_SIZE bounties from one weakness category, which rotates each week,
        worth WEEKLY_BONUS x their open value, due at the end of Sunday.

Challenge bounties are their own BOUNTY rows (Type daily/weekly) pointing at the same
CVE as the open bounty; a user can only get points once per CVE.
"""
import random
from datetime import timedelta

from django.db import transaction

from CvePatcherApp.models import Bounty

DAILY_BONUS = 1.5
DAILY_MIN_VALUE = 300  # pick from bounties at least this valuable
DAILY_POOL = 500  # ... and among the top this many of them by urgency
WEEKLY_BONUS = 1.25
WEEKLY_SIZE = 5
WEEKLY_THEMES = [
    ('memory', 'Memory Safety Week'),
    ('injection', 'Injection Week'),
    ('access', 'Access Control Week'),
    ('other', 'Wildcard Week'),
]


def _round5(value):
    return int(round(value / 5) * 5)


def _copy(open_bounty, kind, title, bonus, due):
    return Bounty(
        Cve_Id=open_bounty.Cve_Id,
        Type=kind,
        Title=title,
        Value=_round5(open_bounty.Value * bonus),
        Due_Date=due,
        Severity=open_bounty.Severity,
        Urgency=open_bounty.Urgency,
        Difficulty=open_bounty.Difficulty,
        Rarity=open_bounty.Rarity,
        Impact_Source=open_bounty.Impact_Source,
    )


@transaction.atomic
def daily(day):
    """Return the daily challenge for day, creating it if needed (None if no bounties)."""
    due = day + timedelta(days=1)
    existing = Bounty.objects.filter(Type=Bounty.DAILY, Due_Date=due).first()
    if existing:
        return existing
    used = Bounty.objects.filter(Type=Bounty.DAILY).values('Cve_Id')
    pool = list(
        Bounty.objects.filter(Type=Bounty.OPEN, Value__gte=DAILY_MIN_VALUE)
        .exclude(Cve_Id__in=used)
        .select_related('Cve_Id')
        .order_by('-Urgency')[:DAILY_POOL]
    )
    if not pool:
        return None
    pick = random.Random(day.isoformat()).choice(pool)
    bounty = _copy(pick, Bounty.DAILY, f'Daily challenge {day.isoformat()}', DAILY_BONUS, due)
    bounty.save()
    return bounty


@transaction.atomic
def weekly(day):
    """Return this week's challenge bounties (Monday to Sunday), creating them if needed."""
    monday = day - timedelta(days=day.weekday())
    due = monday + timedelta(days=6)
    existing = list(Bounty.objects.filter(Type=Bounty.WEEKLY, Due_Date=due).select_related('Cve_Id'))
    if existing:
        return existing
    used = Bounty.objects.filter(Type=Bounty.WEEKLY).values('Cve_Id')
    # This week's theme, or the next one along if it has no bounties left
    start = monday.isocalendar().week
    picks, title = [], ''
    for offset in range(len(WEEKLY_THEMES)):
        category, title = WEEKLY_THEMES[(start + offset) % len(WEEKLY_THEMES)]
        picks = list(
            Bounty.objects.filter(Type=Bounty.OPEN, Cve_Id__Category=category)
            .exclude(Cve_Id__in=used)
            .select_related('Cve_Id')
            .order_by('-Value')[:WEEKLY_SIZE]
        )
        if picks:
            break
    bounties = [_copy(b, Bounty.WEEKLY, title, WEEKLY_BONUS, due) for b in picks]
    for bounty in bounties:
        bounty.save()
    return bounties
