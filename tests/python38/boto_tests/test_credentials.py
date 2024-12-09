import asyncio
import json
import subprocess
from datetime import datetime, timedelta
from unittest import mock

import botocore.exceptions
import pytest
from dateutil.tz import tzlocal

from aiobotocore import credentials
from aiobotocore.session import AioSession
from tests.boto_tests.test_credentials import full_url


# From class TestRefreshableCredentials(TestCredentials):
@pytest.fixture
def refreshable_creds():
    def _f(mock_time_return_value=None, refresher_return_value='METADATA'):
        refresher = mock.AsyncMock()
        future_time = datetime.now(tzlocal()) + timedelta(hours=24)
        expiry_time = datetime.now(tzlocal()) - timedelta(minutes=30)
        metadata = {
            'access_key': 'NEW-ACCESS',
            'secret_key': 'NEW-SECRET',
            'token': 'NEW-TOKEN',
            'expiry_time': future_time.isoformat(),
            'role_name': 'rolename',
        }
        refresher.return_value = (
            metadata
            if refresher_return_value == 'METADATA'
            else refresher_return_value
        )
        mock_time = mock.Mock()
        mock_time.return_value = mock_time_return_value
        creds = credentials.AioRefreshableCredentials(
            'ORIGINAL-ACCESS',
            'ORIGINAL-SECRET',
            'ORIGINAL-TOKEN',
            expiry_time,
            refresher,
            'iam-role',
            time_fetcher=mock_time,
        )
        return creds

    return _f


# From class TestDeferredRefreshableCredentials(unittest.TestCase):
@pytest.fixture
def deferrable_creds():
    def _f(mock_time_return_value=None, refresher_return_value='METADATA'):
        refresher = mock.AsyncMock()
        future_time = datetime.now(tzlocal()) + timedelta(hours=24)
        metadata = {
            'access_key': 'NEW-ACCESS',
            'secret_key': 'NEW-SECRET',
            'token': 'NEW-TOKEN',
            'expiry_time': future_time.isoformat(),
            'role_name': 'rolename',
        }
        refresher.return_value = (
            metadata
            if refresher_return_value == 'METADATA'
            else refresher_return_value
        )
        mock_time = mock.Mock()
        mock_time.return_value = mock_time_return_value or datetime.now(
            tzlocal()
        )
        creds = credentials.AioDeferredRefreshableCredentials(
            refresher, 'iam-role', time_fetcher=mock_time
        )
        return creds

    return _f


@pytest.mark.moto
@pytest.mark.asyncio
async def test_refreshablecredentials_get_credentials_set(refreshable_creds):
    creds = refreshable_creds(
        mock_time_return_value=(
            datetime.now(tzlocal()) - timedelta(minutes=60)
        )
    )

    assert not creds.refresh_needed()

    credentials_set = await creds.get_frozen_credentials()
    assert isinstance(credentials_set, credentials.ReadOnlyCredentials)
    assert credentials_set.access_key == 'ORIGINAL-ACCESS'
    assert credentials_set.secret_key == 'ORIGINAL-SECRET'
    assert credentials_set.token == 'ORIGINAL-TOKEN'


@pytest.mark.moto
@pytest.mark.asyncio
async def test_refreshablecredentials_refresh_returns_empty_dict(
    refreshable_creds,
):
    creds = refreshable_creds(
        mock_time_return_value=datetime.now(tzlocal()),
        refresher_return_value={},
    )

    assert creds.refresh_needed()

    with pytest.raises(botocore.exceptions.CredentialRetrievalError):
        await creds.get_frozen_credentials()


@pytest.mark.moto
@pytest.mark.asyncio
async def test_refreshablecredentials_refresh_returns_none(refreshable_creds):
    creds = refreshable_creds(
        mock_time_return_value=datetime.now(tzlocal()),
        refresher_return_value=None,
    )

    assert creds.refresh_needed()

    with pytest.raises(botocore.exceptions.CredentialRetrievalError):
        await creds.get_frozen_credentials()


@pytest.mark.moto
@pytest.mark.asyncio
async def test_refreshablecredentials_refresh_returns_partial(
    refreshable_creds,
):
    creds = refreshable_creds(
        mock_time_return_value=datetime.now(tzlocal()),
        refresher_return_value={'access_key': 'akid'},
    )

    assert creds.refresh_needed()

    with pytest.raises(botocore.exceptions.CredentialRetrievalError):
        await creds.get_frozen_credentials()


@pytest.mark.moto
@pytest.mark.asyncio
async def test_deferrablecredentials_get_credentials_set(deferrable_creds):
    creds = deferrable_creds()

    creds._refresh_using.assert_not_called()

    await creds.get_frozen_credentials()
    assert creds._refresh_using.call_count == 1


@pytest.mark.moto
@pytest.mark.asyncio
async def test_deferrablecredentials_refresh_only_called_once(
    deferrable_creds,
):
    creds = deferrable_creds()

    creds._refresh_using.assert_not_called()

    for _ in range(5):
        await creds.get_frozen_credentials()

    assert creds._refresh_using.call_count == 1


# From class TestInstanceMetadataProvider(BaseEnvVar):
@pytest.mark.moto
@pytest.mark.asyncio
async def test_instancemetadata_load():
    timeobj = datetime.now(tzlocal())
    timestamp = (timeobj + timedelta(hours=24)).isoformat()

    fetcher = mock.AsyncMock()
    fetcher.retrieve_iam_role_credentials = mock.AsyncMock(
        return_value={
            'access_key': 'a',
            'secret_key': 'b',
            'token': 'c',
            'expiry_time': timestamp,
            'role_name': 'myrole',
        }
    )

    provider = credentials.AioInstanceMetadataProvider(
        iam_role_fetcher=fetcher
    )
    creds = await provider.load()
    assert creds is not None
    assert creds.method == 'iam-role'

    creds = await creds.get_frozen_credentials()
    assert creds.access_key == 'a'
    assert creds.secret_key == 'b'
    assert creds.token == 'c'


@pytest.mark.moto
@pytest.mark.asyncio
async def test_containerprovider_assume_role_no_cache():
    environ = {
        'AWS_CONTAINER_CREDENTIALS_RELATIVE_URI': '/latest/credentials?id=foo'
    }
    fetcher = mock.AsyncMock()
    fetcher.full_url = full_url

    timeobj = datetime.now(tzlocal())
    timestamp = (timeobj + timedelta(hours=24)).isoformat()
    fetcher.retrieve_full_uri.return_value = {
        "AccessKeyId": "access_key",
        "SecretAccessKey": "secret_key",
        "Token": "token",
        "Expiration": timestamp,
    }
    provider = credentials.AioContainerProvider(environ, fetcher)
    # Will return refreshable credentials
    creds = await provider.load()

    url = full_url('/latest/credentials?id=foo')
    fetcher.retrieve_full_uri.assert_called_with(url, headers=None)

    assert creds.method == 'container-role'

    creds = await creds.get_frozen_credentials()
    assert creds.access_key == 'access_key'
    assert creds.secret_key == 'secret_key'
    assert creds.token == 'token'


# From class TestProcessProvider
@pytest.fixture()
def process_provider():
    def _f(profile_name='default', loaded_config=None, invoked_process=None):
        load_config = mock.Mock(return_value=loaded_config)
        popen_mock = mock.Mock(
            return_value=invoked_process or mock.Mock(),
            spec=asyncio.create_subprocess_exec,
        )
        return popen_mock, credentials.AioProcessProvider(
            profile_name, load_config, popen=popen_mock
        )

    return _f


@pytest.mark.moto
@pytest.mark.asyncio
async def test_processprovider_retrieve_refereshable_creds(process_provider):
    config = {
        'profiles': {'default': {'credential_process': 'my-process /somefile'}}
    }
    invoked_process = mock.AsyncMock()
    stdout = json.dumps(
        {
            'Version': 1,
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            'Expiration': '2999-01-01T00:00:00Z',
        }
    )
    invoked_process.communicate.return_value = (stdout.encode('utf-8'), b'')
    invoked_process.returncode = 0

    popen_mock, provider = process_provider(
        loaded_config=config, invoked_process=invoked_process
    )
    creds = await provider.load()
    assert isinstance(creds, credentials.AioRefreshableCredentials)
    assert creds is not None
    assert creds.method == 'custom-process'

    creds = await creds.get_frozen_credentials()
    assert creds.access_key == 'foo'
    assert creds.secret_key == 'bar'
    assert creds.token == 'baz'
    popen_mock.assert_called_with(
        'my-process',
        '/somefile',
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


@pytest.mark.moto
@pytest.mark.asyncio
async def test_processprovider_retrieve_creds(process_provider):
    config = {'profiles': {'default': {'credential_process': 'my-process'}}}
    invoked_process = mock.AsyncMock()
    stdout = json.dumps(
        {
            'Version': 1,
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
        }
    )
    invoked_process.communicate.return_value = (stdout.encode('utf-8'), b'')
    invoked_process.returncode = 0

    popen_mock, provider = process_provider(
        loaded_config=config, invoked_process=invoked_process
    )
    creds = await provider.load()
    assert isinstance(creds, credentials.AioCredentials)
    assert creds is not None
    assert creds.access_key == 'foo'
    assert creds.secret_key == 'bar'
    assert creds.token == 'baz'
    assert creds.method == 'custom-process'


@pytest.mark.moto
@pytest.mark.asyncio
async def test_processprovider_bad_version(process_provider):
    config = {'profiles': {'default': {'credential_process': 'my-process'}}}
    invoked_process = mock.AsyncMock()
    stdout = json.dumps(
        {
            'Version': 2,
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            'Expiration': '2999-01-01T00:00:00Z',
        }
    )
    invoked_process.communicate.return_value = (stdout.encode('utf-8'), b'')
    invoked_process.returncode = 0

    popen_mock, provider = process_provider(
        loaded_config=config, invoked_process=invoked_process
    )
    with pytest.raises(botocore.exceptions.CredentialRetrievalError):
        await provider.load()


@pytest.mark.moto
@pytest.mark.asyncio
async def test_processprovider_missing_field(process_provider):
    config = {'profiles': {'default': {'credential_process': 'my-process'}}}
    invoked_process = mock.AsyncMock()
    stdout = json.dumps(
        {
            'Version': 1,
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            'Expiration': '2999-01-01T00:00:00Z',
        }
    )
    invoked_process.communicate.return_value = (stdout.encode('utf-8'), b'')
    invoked_process.returncode = 0

    popen_mock, provider = process_provider(
        loaded_config=config, invoked_process=invoked_process
    )
    with pytest.raises(botocore.exceptions.CredentialRetrievalError):
        await provider.load()


@pytest.mark.moto
@pytest.mark.asyncio
async def test_processprovider_bad_exitcode(process_provider):
    config = {'profiles': {'default': {'credential_process': 'my-process'}}}
    invoked_process = mock.AsyncMock()
    stdout = 'lah'
    invoked_process.communicate.return_value = (stdout.encode('utf-8'), b'')
    invoked_process.returncode = 1

    popen_mock, provider = process_provider(
        loaded_config=config, invoked_process=invoked_process
    )
    with pytest.raises(botocore.exceptions.CredentialRetrievalError):
        await provider.load()


@pytest.mark.moto
@pytest.mark.asyncio
async def test_processprovider_bad_config(process_provider):
    config = {'profiles': {'default': {'credential_process': None}}}
    invoked_process = mock.AsyncMock()
    stdout = json.dumps(
        {
            'Version': 2,
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            'Expiration': '2999-01-01T00:00:00Z',
        }
    )
    invoked_process.communicate.return_value = (stdout.encode('utf-8'), b'')
    invoked_process.returncode = 0

    popen_mock, provider = process_provider(
        loaded_config=config, invoked_process=invoked_process
    )
    creds = await provider.load()
    assert creds is None


@pytest.mark.moto
@pytest.mark.asyncio
async def test_session_credentials():
    with mock.patch(
        'aiobotocore.credentials.AioCredential' 'Resolver.load_credentials'
    ) as mock_obj:
        mock_obj.return_value = 'somecreds'

        session = AioSession()
        creds = await session.get_credentials()
        assert creds == 'somecreds'
