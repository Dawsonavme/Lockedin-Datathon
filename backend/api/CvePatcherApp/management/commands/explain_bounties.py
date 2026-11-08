"""Ask Granite ahead of time for the explanations a demo is likely to show.

Covers today's daily and weekly challenges plus the top open bounties by value, so
their "In plain words" panel loads instantly. CVEs that already have one are skipped.

Usage: python manage.py explain_bounties [--top 200] [--workers 16]
"""
from concurrent.futures import ThreadPoolExecutor, as_completed

from django.core.management.base import BaseCommand
from django.utils import timezone

from CvePatcherApp import challenges, explain
from CvePatcherApp.models import Bounty, Cve


class Command(BaseCommand):
    help = __doc__.splitlines()[0]

    def add_arguments(self, parser):
        parser.add_argument('--top', type=int, default=200, help='how many of the highest-value open bounties')
        parser.add_argument('--workers', type=int, default=16, help='Granite requests to send at once')

    def handle(self, *args, top, workers, **options):
        today = timezone.localdate()
        wanted = [challenges.daily(today).Cve_Id_id]
        wanted += [b.Cve_Id_id for b in challenges.weekly(today)]
        wanted += Bounty.objects.filter(Type=Bounty.OPEN).order_by('-Value').values_list('Cve_Id', flat=True)[:top]
        todo = list(Cve.objects.filter(Cve_Id__in=wanted, Explanation=''))
        self.stdout.write(f'{len(set(wanted)):,} CVEs wanted, {len(todo):,} need an explanation')

        # Granite calls run in parallel; saving stays on this thread, since SQLite allows one writer
        done = failed = 0
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(explain.ask_granite, cve): cve for cve in todo}
            for future in as_completed(futures):
                cve = futures[future]
                try:
                    cve.Explanation = future.result()
                except explain.GraniteUnavailable as e:
                    failed += 1
                    self.stderr.write(f'{cve.Cve_Id}: {e}')
                    continue
                cve.save(update_fields=['Explanation'])
                done += 1
                if done % 25 == 0:
                    self.stdout.write(f'  {done:,} / {len(todo):,}')
        self.stdout.write(self.style.SUCCESS(f'Explained {done:,} CVEs ({failed:,} failed)'))
