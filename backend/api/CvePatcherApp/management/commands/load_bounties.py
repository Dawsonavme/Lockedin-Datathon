"""Load one month of bounty scores from the Bounty pipeline into the database.

Creates or updates one CVE row and one open BOUNTY row per scored CVE. Run it again
after re-scoring and the open bounties pick up the new values; completed
registrations keep the points they locked in.

Usage: python manage.py load_bounties [--month 2025-12] [--limit 1000]
"""
from pathlib import Path

import pandas as pd
from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import transaction

from CvePatcherApp.models import Bounty, Cve

DATA = Path(settings.BASE_DIR).parent / 'Bounty' / 'assets' / 'data'
BATCH = 2000
CVE_FIELDS = ['Name', 'Description', 'Published', 'Cvss3_Score', 'Cvss3_Severity', 'Cwe_Id', 'Cwe_Name',
              'Category', 'Fix_Type', 'In_Kev']
FACTOR_FIELDS = ['Value', 'Severity', 'Urgency', 'Difficulty', 'Rarity', 'Impact_Source']


def blank(value):
    """NaN -> '' for text columns."""
    return '' if pd.isna(value) else value


def none(value):
    """NaN -> None for nullable number and date columns."""
    return None if pd.isna(value) else value


class Command(BaseCommand):
    help = 'Load bounty scores for one month into the CVE and BOUNTY tables.'

    def add_arguments(self, parser):
        parser.add_argument('--month', default='2025-12', help='scores month to load (YYYY-MM)')
        parser.add_argument('--limit', type=int, help='load only the N highest-value bounties')
        parser.add_argument('--data', type=Path, default=DATA, help='Bounty assets/data folder')

    def handle(self, *args, month, limit, data, **options):
        scores = pd.read_csv(data / 'parsed' / 'bounty_scores.csv')
        scores = scores[scores['month'] == f'{month}-01'].dropna(subset=['points'])
        if scores.empty:
            raise SystemExit(f'no scored rows for {month}; run src/bounty/score.py first')
        scores = scores.sort_values('points', ascending=False)
        if limit:
            scores = scores.head(limit)

        vulns = pd.read_csv(
            data / 'vulnerabilities.csv',
            usecols=['cve_id', 'description', 'published', 'cvss3_score', 'cvss3_severity', 'cwe_ids'],
            low_memory=False,
        )
        vulns = vulns[vulns['cve_id'].isin(scores['cve_id'])]
        vulns['cvss3_score'] = pd.to_numeric(vulns['cvss3_score'], errors='coerce')
        vulns['published'] = pd.to_datetime(vulns['published'], errors='coerce').dt.date
        vulns['cwe_id'] = vulns['cwe_ids'].str.split(';').str[0].str.strip()
        names = pd.read_csv(data / 'weakness_types.csv', usecols=['cwe_id', 'name'])
        vulns = vulns.merge(names.rename(columns={'name': 'cwe_name'}), on='cwe_id', how='left')
        kev_names = pd.read_csv(data / 'known_exploited.csv', usecols=['cve_id', 'name'])
        kev = dict(zip(kev_names['cve_id'], kev_names['name'].fillna('')))

        rows = scores.merge(vulns, on='cve_id', how='inner')
        self.stdout.write(f'Loading {len(rows):,} bounties for {month}')

        cves = [
            Cve(
                Cve_Id=r.cve_id,
                Name=kev.get(r.cve_id, ''),
                Description=r.description,
                Published=none(r.published),
                Cvss3_Score=none(r.cvss3_score),
                Cvss3_Severity=blank(r.cvss3_severity),
                Cwe_Id=blank(r.cwe_id),
                Cwe_Name=blank(r.cwe_name),
                Category=blank(r.category),
                Fix_Type=blank(r.fix_type),
                In_Kev=r.cve_id in kev,
            )
            for r in rows.itertuples(index=False)
        ]
        factors = {
            r.cve_id: {
                'Value': int(r.points),
                'Severity': r.severity,
                'Urgency': r.urgency,
                'Difficulty': r.difficulty,
                'Rarity': r.rarity,
                'Impact_Source': blank(r.impact_source),
            }
            for r in rows.itertuples(index=False)
        }

        with transaction.atomic():
            Cve.objects.bulk_create(
                cves, batch_size=BATCH, update_conflicts=True,
                unique_fields=['Cve_Id'], update_fields=CVE_FIELDS,
            )
            existing = {b.Cve_Id_id: b for b in Bounty.objects.filter(Type=Bounty.OPEN)}
            to_update, to_create = [], []
            for cve_id, values in factors.items():
                bounty = existing.get(cve_id) or Bounty(Cve_Id_id=cve_id, Type=Bounty.OPEN)
                for field, value in values.items():
                    setattr(bounty, field, value)
                (to_update if bounty.pk else to_create).append(bounty)
            Bounty.objects.bulk_update(to_update, FACTOR_FIELDS, batch_size=BATCH)
            Bounty.objects.bulk_create(to_create, batch_size=BATCH)

        self.stdout.write(self.style.SUCCESS(
            f'{len(cves):,} CVEs; {len(to_create):,} bounties created, {len(to_update):,} updated'
        ))
