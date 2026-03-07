from unittest import mock

from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APITestCase
from firebase_admin import auth as firebase_auth
from drf_firebase_auth.settings import api_settings
from drf_firebase_auth.utils import map_firebase_uid_to_username, map_firebase_email_to_username

User = get_user_model()
# Firebase initialization is now lazy in the authentication class


class WhoAmITests(APITestCase):

    def setUp(self):
        self._url = reverse('whoami')
        self._test_user_email = 'user@example.com'
        self._id_token_endpoint = (
            'https://identitytoolkit.googleapis.com/v1/accounts'
            ':signInWithCustomToken?key={api_key}')
        self._MOCK_FIREBASE_CREATE_LOCAL_USER_FALSE = mock.patch(
            'drf_firebase_auth.authentication.api_settings'
            '.FIREBASE_CREATE_LOCAL_USER',
            new=False)
        self._MOCK_FIREBASE_CREATE_LOCAL_USER_TRUE = mock.patch(
            'drf_firebase_auth.authentication.api_settings'
            '.FIREBASE_CREATE_LOCAL_USER',
            new=True)
        self._MOCK_FIREBASE_USERNAME_MAPPING_FUNC_UID = mock.patch(
            'drf_firebase_auth.authentication.api_settings'
            '.FIREBASE_USERNAME_MAPPING_FUNC',
            new=map_firebase_uid_to_username)
        self._MOCK_FIREBASE_USERNAME_MAPPING_FUNC_EMAIL = mock.patch(
            'drf_firebase_auth.authentication.api_settings'
            '.FIREBASE_USERNAME_MAPPING_FUNC',
            new=map_firebase_email_to_username)

    def _get_mock_user(self, uid='test-uid', email='user@example.com'):
        mock_user = mock.MagicMock(spec=firebase_auth.UserRecord)
        mock_user.uid = uid
        mock_user.email = email
        mock_user.display_name = 'Test User'
        mock_user.provider_data = []
        return mock_user

    @mock.patch('drf_firebase_auth.authentication.get_firebase_app')
    @mock.patch('drf_firebase_auth.authentication.firebase_auth.get_user')
    @mock.patch(
        'drf_firebase_auth.authentication.firebase_auth.verify_id_token')
    def test_authenticated_request(self, mock_verify, mock_get_user, mock_app):
        """ ensure we can auth with a valid id token """
        uid = 'test-uid-123'
        mock_verify.return_value = {'uid': uid}
        mock_get_user.return_value = self._get_mock_user(uid=uid)

        self.client.credentials(
            HTTP_AUTHORIZATION=
            f'{api_settings.FIREBASE_AUTH_HEADER_PREFIX} valid-token')

        with self._MOCK_FIREBASE_CREATE_LOCAL_USER_FALSE:
            response = self.client.get(self._url)
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        with self._MOCK_FIREBASE_CREATE_LOCAL_USER_TRUE:
            response = self.client.get(self._url)
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(response.data['request.auth']['uid'], uid)

    def test_unauthenticated_request(self):
        """ ensure we cannot auth without a valid id token """
        response = self.client.get(self._url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    @mock.patch('drf_firebase_auth.authentication.get_firebase_app')
    @mock.patch(
        'drf_firebase_auth.authentication.firebase_auth.verify_id_token')
    def test_invalid_token_request(self, mock_verify, mock_app):
        """ ensure we cannot auth with an invalid id token """
        mock_verify.side_effect = Exception("Invalid token")

        self.client.credentials(
            HTTP_AUTHORIZATION=
            f'{api_settings.FIREBASE_AUTH_HEADER_PREFIX} invalid-token')
        response = self.client.get(self._url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    @mock.patch('drf_firebase_auth.authentication.get_firebase_app')
    @mock.patch('drf_firebase_auth.authentication.firebase_auth.get_user')
    @mock.patch(
        'drf_firebase_auth.authentication.firebase_auth.verify_id_token')
    def test_user_creation_uid_as_username(self, mock_verify, mock_get_user,
                                           mock_app):
        """ ensure user is created dependent on FIREBASE_CREATE_LOCAL_USER """
        uid = 'test-uid-456'
        email = 'newuser@example.com'
        mock_verify.return_value = {'uid': uid}
        mock_get_user.return_value = self._get_mock_user(uid=uid, email=email)

        self.client.credentials(
            HTTP_AUTHORIZATION=
            f'{api_settings.FIREBASE_AUTH_HEADER_PREFIX} some-token')

        with self._MOCK_FIREBASE_CREATE_LOCAL_USER_FALSE:
            before_count = User.objects.count()
            response = self.client.get(self._url)
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
            self.assertEqual(User.objects.count(), before_count)

        with self._MOCK_FIREBASE_CREATE_LOCAL_USER_TRUE:
            with self._MOCK_FIREBASE_USERNAME_MAPPING_FUNC_UID:
                before_count = User.objects.count()
                response = self.client.get(self._url)
                self.assertEqual(response.status_code, status.HTTP_200_OK)
                self.assertEqual(User.objects.count(), before_count + 1)
                self.assertIsNotNone(User.objects.filter(email=email).first())
                self.assertIsNotNone(User.objects.filter(username=uid).first())

    @mock.patch('drf_firebase_auth.authentication.get_firebase_app')
    @mock.patch('drf_firebase_auth.authentication.firebase_auth.get_user')
    @mock.patch(
        'drf_firebase_auth.authentication.firebase_auth.verify_id_token')
    def test_user_creation_email_as_username(self, mock_verify, mock_get_user,
                                             mock_app):
        """ ensure user is created dependent on FIREBASE_CREATE_LOCAL_USER """
        uid = 'test-uid-789'
        email = 'emailuser@example.com'
        mock_verify.return_value = {'uid': uid}
        mock_get_user.return_value = self._get_mock_user(uid=uid, email=email)

        self.client.credentials(
            HTTP_AUTHORIZATION=
            f'{api_settings.FIREBASE_AUTH_HEADER_PREFIX} some-token')

        with self._MOCK_FIREBASE_CREATE_LOCAL_USER_FALSE:
            before_count = User.objects.count()
            response = self.client.get(self._url)
            self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
            self.assertEqual(User.objects.count(), before_count)

        with self._MOCK_FIREBASE_CREATE_LOCAL_USER_TRUE:
            with self._MOCK_FIREBASE_USERNAME_MAPPING_FUNC_EMAIL:
                before_count = User.objects.count()
                response = self.client.get(self._url)
                self.assertEqual(response.status_code, status.HTTP_200_OK)
                self.assertEqual(User.objects.count(), before_count + 1)
                self.assertIsNotNone(User.objects.filter(email=email).first())
                self.assertIsNotNone(
                    User.objects.filter(username=email).first())


class ProviderPersistenceTests(APITestCase):

    def setUp(self):
        self._url = reverse('whoami')
        self._uid = 'test-uid-123'
        self._email = 'test@example.com'

        # Create local user and firebase records
        self.user = User.objects.create_user(username='testuser',
                                             email=self._email)
        from drf_firebase_auth.models import FirebaseUser, FirebaseUserProvider
        self.fb_user = FirebaseUser.objects.create(user=self.user,
                                                   uid=self._uid)
        self.provider = FirebaseUserProvider.objects.create(
            firebase_user=self.fb_user,
            provider_id='google.com',
            uid='google-uid-123')

    @mock.patch('drf_firebase_auth.authentication.get_firebase_app')
    @mock.patch('drf_firebase_auth.authentication.firebase_auth.get_user')
    @mock.patch(
        'drf_firebase_auth.authentication.firebase_auth.verify_id_token')
    def test_provider_persistence(self, mock_verify, mock_get_user, mock_app):
        """
        Ensure existing provider records are NOT deleted when logging in.
        """
        # Mock verification
        mock_verify.return_value = {
            'uid': self._uid,
            'email': self._email,
            'email_verified': True,
        }

        # Mock UserRecord from Firebase
        mock_user = mock.MagicMock(spec=firebase_auth.UserRecord)
        mock_user.uid = self._uid
        mock_user.email = self._email
        mock_user.display_name = 'Test User'

        mock_provider = mock.MagicMock()
        mock_provider.provider_id = 'google.com'
        mock_provider.uid = 'google-uid-123'
        mock_user.provider_data = [mock_provider]

        mock_get_user.return_value = mock_user

        self.client.credentials(
            HTTP_AUTHORIZATION=
            f'{api_settings.FIREBASE_AUTH_HEADER_PREFIX} some-token')

        from drf_firebase_auth.models import FirebaseUserProvider

        # Before request
        self.assertEqual(FirebaseUserProvider.objects.count(), 1)

        response = self.client.get(self._url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # After request - Provider should still exist!
        self.assertEqual(FirebaseUserProvider.objects.count(), 1,
                         "Provider record was incorrectly deleted!")
        self.assertEqual(FirebaseUserProvider.objects.first().provider_id,
                         'google.com')

    @mock.patch('drf_firebase_auth.authentication.get_firebase_app')
    @mock.patch('drf_firebase_auth.authentication.firebase_auth.get_user')
    @mock.patch(
        'drf_firebase_auth.authentication.firebase_auth.verify_id_token')
    def test_provider_sync(self, mock_verify, mock_get_user, mock_app):
        """
        Ensure new provider records ARE added and old ones removed if changed in Firebase.
        """
        # Mock verification
        mock_verify.return_value = {
            'uid': self._uid,
            'email': self._email,
            'email_verified': True,
        }

        # Mock UserRecord with DIFFERENT provider
        mock_user = mock.MagicMock(spec=firebase_auth.UserRecord)
        mock_user.uid = self._uid
        mock_user.email = self._email
        mock_user.display_name = 'Test User'

        mock_provider = mock.MagicMock()
        mock_provider.provider_id = 'facebook.com'
        mock_provider.uid = 'fb-uid-123'
        mock_user.provider_data = [mock_provider]

        mock_get_user.return_value = mock_user

        self.client.credentials(
            HTTP_AUTHORIZATION=
            f'{api_settings.FIREBASE_AUTH_HEADER_PREFIX} some-token')

        from drf_firebase_auth.models import FirebaseUserProvider

        response = self.client.get(self._url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # After request - Provider should have changed
        providers = FirebaseUserProvider.objects.all()
        self.assertEqual(providers.count(), 1)
        self.assertEqual(providers[0].provider_id, 'facebook.com')
        self.assertEqual(providers[0].uid, 'fb-uid-123')
