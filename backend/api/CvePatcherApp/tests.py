import json
from datetime import date, timedelta

from django.test import TestCase
from django.utils import timezone

from CvePatcherApp import challenges
from CvePatcherApp.models import Bounty, Cve, Sponsor, User, UserRegisteredBounty

# Create your tests here.


def make_bounty(cve_id, value=300, category='memory', urgency=1.0, **extra):
    cve = Cve.objects.create(Cve_Id=cve_id, Description=f'{cve_id} description', Category=category)
    return Bounty.objects.create(Cve_Id=cve, Value=value, Urgency=urgency, **extra)


class ApiTestCase(TestCase):
    def call(self, method, url, data=None, token=None):
        headers = {'HTTP_AUTHORIZATION': f'Token {token}'} if token else {}
        body = json.dumps(data) if data is not None else None
        return getattr(self.client, method)(url, body, content_type='application/json', **headers)

    def signup(self, name, role='user'):
        response = self.call('post', '/auth/signup', {
            'Name': name, 'Email': f'{name}@example.com', 'Password': 'correct-horse-1', 'Role': role,
        })
        self.assertEqual(response.status_code, 201, response.content)
        return response.json()['Token']


class CrudTests(ApiTestCase):
    """Her CRUD endpoints, including the cases that used to crash."""

    def test_passwords_are_hashed_and_never_returned(self):
        self.call('post', '/users', {'Name': 'Ann', 'Email': 'ann@x.io', 'Password': 'secret123'})
        self.assertNotIn('Password', self.call('get', '/users').json()[0])
        self.assertNotEqual(User.objects.get().Password, 'secret123')
        self.assertTrue(User.objects.get().check_password('secret123'))

    def test_points_cannot_be_set_directly(self):
        self.call('post', '/users', {'Name': 'Ann', 'Email': 'ann@x.io', 'Password': 'secret123', 'Earned_Points': 9999})
        self.assertEqual(User.objects.get().Earned_Points, 0)

    def test_get_one_and_update_user(self):
        self.call('post', '/users', {'Name': 'Ann', 'Email': 'ann@x.io', 'Password': 'secret123'})
        user_id = User.objects.get().User_Id
        self.assertEqual(self.call('get', f'/users/{user_id}').json()['Name'], 'Ann')
        response = self.call('put', '/users', {'User_Id': user_id, 'Name': 'Ann B'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(User.objects.get().Name, 'Ann B')

    def test_bounty_uses_real_cve_ids_and_can_be_deleted(self):
        Cve.objects.create(Cve_Id='CVE-2024-3400', Description='PAN-OS')
        response = self.call('post', '/bounties', {'Cve_Id': 'CVE-2024-3400', 'Value': 500, 'Type': 'open'})
        self.assertEqual(response.status_code, 200, response.content)
        bounty_id = Bounty.objects.get().Bounty_Id
        self.assertEqual(self.call('delete', f'/bounties/{bounty_id}').status_code, 200)
        self.assertFalse(Bounty.objects.exists())

    def test_registrations_list(self):
        bounty = make_bounty('CVE-1')
        self.call('post', '/users', {'Name': 'Ann', 'Email': 'ann@x.io', 'Password': 'secret123'})
        user = User.objects.get()
        self.call('post', '/userregisteredbounties', {'User_Id': user.pk, 'Bounty_Id': bounty.pk})
        rows = self.call('get', '/userregisteredbounties').json()
        self.assertEqual(rows[0]['Points_Earned'], 0)

    def test_missing_rows_give_404(self):
        self.assertEqual(self.call('get', '/users/99').status_code, 404)
        self.assertEqual(self.call('put', '/users', {'User_Id': 99, 'Name': 'x'}).status_code, 404)
        self.assertEqual(self.call('delete', '/bounties/99').status_code, 404)

    def test_bad_input_gives_400(self):
        self.assertEqual(self.call('post', '/bounties', {'Cve_Id': 'CVE-NOPE', 'Value': 1}).status_code, 400)


class AuthTests(ApiTestCase):
    def test_signup_login_and_me(self):
        self.signup('ann')
        response = self.call('post', '/auth/login', {'Email': 'ann@example.com', 'Password': 'correct-horse-1'})
        self.assertEqual(response.status_code, 200)
        me = self.call('get', '/me', token=response.json()['Token']).json()
        self.assertEqual((me['Role'], me['Name'], me['Earned_Points']), ('user', 'ann', 0))

    def test_wrong_password_is_rejected(self):
        self.signup('ann')
        response = self.call('post', '/auth/login', {'Email': 'ann@example.com', 'Password': 'nope'})
        self.assertEqual(response.status_code, 401)

    def test_forged_token_is_rejected(self):
        self.assertEqual(self.call('get', '/me', token='made-up').status_code, 401)


class BoardTests(ApiTestCase):
    def setUp(self):
        make_bounty('CVE-1', value=100, category='memory')
        make_bounty('CVE-2', value=900, category='injection')
        make_bounty('CVE-3', value=500, category='memory')

    def ids(self, url):
        return [b['Cve']['Cve_Id'] for b in self.call('get', url).json()['Results']]

    def test_default_sort_is_highest_value_first(self):
        self.assertEqual(self.ids('/board'), ['CVE-2', 'CVE-3', 'CVE-1'])

    def test_filter_by_category(self):
        self.assertEqual(self.ids('/board?Category=memory'), ['CVE-3', 'CVE-1'])

    def test_unknown_sort_falls_back_to_value(self):
        self.assertEqual(self.ids('/board?Sort=Password'), ['CVE-2', 'CVE-3', 'CVE-1'])


class GameTests(ApiTestCase):
    def setUp(self):
        self.bounty = make_bounty('CVE-1', value=300)
        self.token = self.signup('ann')

    def complete(self, bounty):
        self.call('post', f'/board/{bounty.pk}/register', token=self.token)
        return self.call('post', f'/board/{bounty.pk}/complete', token=self.token)

    def test_completing_awards_and_locks_points(self):
        self.assertEqual(self.complete(self.bounty).json()['Points_Earned'], 300)
        Bounty.objects.filter(pk=self.bounty.pk).update(Value=999)  # later re-score
        self.assertEqual(UserRegisteredBounty.objects.get().Points_Earned, 300)
        self.assertEqual(User.objects.get().Earned_Points, 300)

    def test_cannot_complete_without_accepting(self):
        response = self.call('post', f'/board/{self.bounty.pk}/complete', token=self.token)
        self.assertEqual(response.status_code, 404)

    def test_cannot_complete_twice(self):
        self.complete(self.bounty)
        response = self.call('post', f'/board/{self.bounty.pk}/complete', token=self.token)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(User.objects.get().Earned_Points, 300)

    def test_points_only_once_per_cve(self):
        self.complete(self.bounty)
        challenge = Bounty.objects.create(Cve_Id=self.bounty.Cve_Id, Type='daily', Value=450,
                                          Due_Date=timezone.localdate() + timedelta(days=1))
        self.assertEqual(self.complete(challenge).status_code, 400)
        self.assertEqual(User.objects.get().Earned_Points, 300)

    def test_expired_challenge_cannot_be_accepted(self):
        expired = Bounty.objects.create(Cve_Id=self.bounty.Cve_Id, Type='daily', Value=450,
                                        Due_Date=timezone.localdate() - timedelta(days=1))
        response = self.call('post', f'/board/{expired.pk}/register', token=self.token)
        self.assertEqual(response.status_code, 400)

    def test_sponsor_points_add_to_reward(self):
        sponsor = self.signup('acme', role='sponsor')
        response = self.call('post', f'/board/{self.bounty.pk}/addpoints', {'Points': 200}, token=sponsor)
        self.assertEqual(response.json()['Total_Value'], 500)
        self.call('post', f'/board/{self.bounty.pk}/addpoints', {'Points': 50}, token=sponsor)
        self.assertEqual(self.complete(self.bounty).json()['Points_Earned'], 550)

    def test_users_cannot_add_points(self):
        response = self.call('post', f'/board/{self.bounty.pk}/addpoints', {'Points': 200}, token=self.token)
        self.assertEqual(response.status_code, 403)

    def test_leaderboard(self):
        self.complete(self.bounty)
        self.assertEqual(self.call('get', '/leaderboard').json()[0]['Earned_Points'], 300)


class ChallengeTests(TestCase):
    def setUp(self):
        for i in range(10):
            make_bounty(f'CVE-M{i}', value=300 + i * 10, category='memory', urgency=i)
            make_bounty(f'CVE-I{i}', value=300 + i * 10, category='injection', urgency=i)

    def test_daily_is_stable_within_a_day_and_pays_bonus(self):
        day = date(2026, 11, 9)
        first, second = challenges.daily(day), challenges.daily(day)
        self.assertEqual(first.pk, second.pk)
        open_value = Bounty.objects.get(Type='open', Cve_Id=first.Cve_Id).Value
        self.assertEqual(first.Value, round(open_value * challenges.DAILY_BONUS / 5) * 5)
        self.assertEqual(first.Due_Date, day + timedelta(days=1))

    def test_daily_does_not_repeat_a_cve(self):
        picks = {challenges.daily(date(2026, 11, d)).Cve_Id_id for d in range(1, 8)}
        self.assertEqual(len(picks), 7)

    def test_weekly_is_one_themed_set_per_week(self):
        monday = date(2026, 11, 9)
        bounties = challenges.weekly(monday)
        self.assertEqual(len(bounties), challenges.WEEKLY_SIZE)
        self.assertEqual(len({b.Cve_Id.Category for b in bounties}), 1)
        self.assertEqual([b.pk for b in challenges.weekly(monday + timedelta(days=3))], [b.pk for b in bounties])
        self.assertEqual(bounties[0].Due_Date, monday + timedelta(days=6))

    def test_challenges_endpoint(self):
        response = self.client.get('/challenges')
        self.assertEqual(response.status_code, 200)
        self.assertIsNotNone(response.json()['Daily'])
        self.assertIn('Bounties', response.json()['Weekly'])
