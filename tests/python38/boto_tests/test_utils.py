import json
import unittest
from unittest import mock

import pytest
from botocore.exceptions import (
    ConnectionClosedError,
    ConnectTimeoutError,
    ReadTimeoutError,
)
from botocore.utils import MetadataRetrievalError

from aiobotocore import utils
from aiobotocore.awsrequest import AioAWSResponse
from aiobotocore.utils import AioInstanceMetadataFetcher
from tests.boto_tests.test_utils import fake_aiohttp_session
from tests.test_response import AsyncBytesIO


class TestInstanceMetadataFetcher(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        urllib3_session_send = 'aiobotocore.httpsession.AIOHTTPSession.send'
        self._urllib3_patch = mock.patch(urllib3_session_send)
        self._send = self._urllib3_patch.start()
        self._imds_responses = []
        self._send.side_effect = self.get_imds_response
        self._role_name = 'role-name'
        self._creds = {
            'AccessKeyId': 'spam',
            'SecretAccessKey': 'eggs',
            'Token': 'spam-token',
            'Expiration': 'something',
        }
        self._expected_creds = {
            'access_key': self._creds['AccessKeyId'],
            'secret_key': self._creds['SecretAccessKey'],
            'token': self._creds['Token'],
            'expiry_time': self._creds['Expiration'],
            'role_name': self._role_name,
        }

    async def asyncTearDown(self):
        self._urllib3_patch.stop()

    def add_imds_response(self, body, status_code=200):
        response = AioAWSResponse(
            url='http://169.254.169.254/',
            status_code=status_code,
            headers={},
            raw=AsyncBytesIO(body),
        )

        self._imds_responses.append(response)

    def add_get_role_name_imds_response(self, role_name=None):
        if role_name is None:
            role_name = self._role_name
        self.add_imds_response(body=role_name.encode('utf-8'))

    def add_get_credentials_imds_response(self, creds=None):
        if creds is None:
            creds = self._creds
        self.add_imds_response(body=json.dumps(creds).encode('utf-8'))

    def add_get_token_imds_response(self, token, status_code=200):
        self.add_imds_response(
            body=token.encode('utf-8'), status_code=status_code
        )

    def add_metadata_token_not_supported_response(self):
        self.add_imds_response(b'', status_code=404)

    def add_imds_connection_error(self, exception):
        self._imds_responses.append(exception)

    def get_imds_response(self, *args, **kwargs):
        response = self._imds_responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    @pytest.mark.moto
    @pytest.mark.asyncio
    async def test_disabled_by_environment(self):
        env = {'AWS_EC2_METADATA_DISABLED': 'true'}
        fetcher = AioInstanceMetadataFetcher(env=env)
        result = await fetcher.retrieve_iam_role_credentials()
        self.assertEqual(result, {})
        self._send.assert_not_called()

    @pytest.mark.moto
    @pytest.mark.asyncio
    async def test_disabled_by_environment_mixed_case(self):
        env = {'AWS_EC2_METADATA_DISABLED': 'tRuE'}
        fetcher = AioInstanceMetadataFetcher(env=env)
        result = await fetcher.retrieve_iam_role_credentials()
        self.assertEqual(result, {})
        self._send.assert_not_called()

    @pytest.mark.moto
    @pytest.mark.asyncio
    async def test_disabling_env_var_not_true(self):
        url = 'https://example.com/'
        env = {'AWS_EC2_METADATA_DISABLED': 'false'}

        self.add_get_token_imds_response(token='token')
        self.add_get_role_name_imds_response()
        self.add_get_credentials_imds_response()

        fetcher = AioInstanceMetadataFetcher(base_url=url, env=env)
        result = await fetcher.retrieve_iam_role_credentials()

        self.assertEqual(result, self._expected_creds)

    @pytest.mark.moto
    @pytest.mark.asyncio
    async def test_includes_user_agent_header(self):
        user_agent = 'my-user-agent'
        self.add_get_token_imds_response(token='token')
        self.add_get_role_name_imds_response()
        self.add_get_credentials_imds_response()

        await AioInstanceMetadataFetcher(
            user_agent=user_agent
        ).retrieve_iam_role_credentials()

        self.assertEqual(self._send.call_count, 3)
        for call in self._send.calls:
            self.assertTrue(call[0][0].headers['User-Agent'], user_agent)

    @pytest.mark.moto
    @pytest.mark.asyncio
    async def test_non_200_response_for_role_name_is_retried(self):
        # Response for role name that have a non 200 status code should
        # be retried.
        self.add_get_token_imds_response(token='token')
        self.add_imds_response(
            status_code=429, body=b'{"message": "Slow down"}'
        )
        self.add_get_role_name_imds_response()
        self.add_get_credentials_imds_response()
        result = await AioInstanceMetadataFetcher(
            num_attempts=2
        ).retrieve_iam_role_credentials()
        self.assertEqual(result, self._expected_creds)

    @pytest.mark.moto
    @pytest.mark.asyncio
    async def test_http_connection_error_for_role_name_is_retried(self):
        # Connection related errors should be retried
        self.add_get_token_imds_response(token='token')
        self.add_imds_connection_error(ConnectionClosedError(endpoint_url=''))
        self.add_get_role_name_imds_response()
        self.add_get_credentials_imds_response()
        result = await AioInstanceMetadataFetcher(
            num_attempts=2
        ).retrieve_iam_role_credentials()
        self.assertEqual(result, self._expected_creds)

    @pytest.mark.moto
    @pytest.mark.asyncio
    async def test_empty_response_for_role_name_is_retried(self):
        # Response for role name that have a non 200 status code should
        # be retried.
        self.add_get_token_imds_response(token='token')
        self.add_imds_response(body=b'')
        self.add_get_role_name_imds_response()
        self.add_get_credentials_imds_response()
        result = await AioInstanceMetadataFetcher(
            num_attempts=2
        ).retrieve_iam_role_credentials()
        self.assertEqual(result, self._expected_creds)

    @pytest.mark.moto
    @pytest.mark.asyncio
    async def test_non_200_response_is_retried(self):
        self.add_get_token_imds_response(token='token')
        self.add_get_role_name_imds_response()
        # Response for creds that has a 200 status code but has an empty
        # body should be retried.
        self.add_imds_response(
            status_code=429, body=b'{"message": "Slow down"}'
        )
        self.add_get_credentials_imds_response()
        result = await AioInstanceMetadataFetcher(
            num_attempts=2
        ).retrieve_iam_role_credentials()
        self.assertEqual(result, self._expected_creds)

    @pytest.mark.moto
    @pytest.mark.asyncio
    async def test_http_connection_errors_is_retried(self):
        self.add_get_token_imds_response(token='token')
        self.add_get_role_name_imds_response()
        # Connection related errors should be retried
        self.add_imds_connection_error(ConnectionClosedError(endpoint_url=''))
        self.add_get_credentials_imds_response()
        result = await AioInstanceMetadataFetcher(
            num_attempts=2
        ).retrieve_iam_role_credentials()
        self.assertEqual(result, self._expected_creds)

    @pytest.mark.moto
    @pytest.mark.asyncio
    async def test_empty_response_is_retried(self):
        self.add_get_token_imds_response(token='token')
        self.add_get_role_name_imds_response()
        # Response for creds that has a 200 status code but is empty.
        # This should be retried.
        self.add_imds_response(body=b'')
        self.add_get_credentials_imds_response()
        result = await AioInstanceMetadataFetcher(
            num_attempts=2
        ).retrieve_iam_role_credentials()
        self.assertEqual(result, self._expected_creds)

    @pytest.mark.moto
    @pytest.mark.asyncio
    async def test_invalid_json_is_retried(self):
        self.add_get_token_imds_response(token='token')
        self.add_get_role_name_imds_response()
        # Response for creds that has a 200 status code but is invalid JSON.
        # This should be retried.
        self.add_imds_response(body=b'{"AccessKey":')
        self.add_get_credentials_imds_response()
        result = await AioInstanceMetadataFetcher(
            num_attempts=2
        ).retrieve_iam_role_credentials()
        self.assertEqual(result, self._expected_creds)

    @pytest.mark.moto
    @pytest.mark.asyncio
    async def test_exhaust_retries_on_role_name_request(self):
        self.add_get_token_imds_response(token='token')
        self.add_imds_response(status_code=400, body=b'')
        result = await AioInstanceMetadataFetcher(
            num_attempts=1
        ).retrieve_iam_role_credentials()
        self.assertEqual(result, {})

    @pytest.mark.moto
    @pytest.mark.asyncio
    async def test_exhaust_retries_on_credentials_request(self):
        self.add_get_token_imds_response(token='token')
        self.add_get_role_name_imds_response()
        self.add_imds_response(status_code=400, body=b'')
        result = await AioInstanceMetadataFetcher(
            num_attempts=1
        ).retrieve_iam_role_credentials()
        self.assertEqual(result, {})

    @pytest.mark.moto
    @pytest.mark.asyncio
    async def test_missing_fields_in_credentials_response(self):
        self.add_get_token_imds_response(token='token')
        self.add_get_role_name_imds_response()
        # Response for creds that has a 200 status code and a JSON body
        # representing an error. We do not necessarily want to retry this.
        self.add_imds_response(
            body=b'{"Code":"AssumeRoleUnauthorizedAccess","Message":"error"}'
        )
        result = (
            await AioInstanceMetadataFetcher().retrieve_iam_role_credentials()
        )
        self.assertEqual(result, {})

    @pytest.mark.moto
    @pytest.mark.asyncio
    async def test_token_is_included(self):
        user_agent = 'my-user-agent'
        self.add_get_token_imds_response(token='token')
        self.add_get_role_name_imds_response()
        self.add_get_credentials_imds_response()

        result = await AioInstanceMetadataFetcher(
            user_agent=user_agent
        ).retrieve_iam_role_credentials()

        # Check that subsequent calls after getting the token include the token.
        self.assertEqual(self._send.call_count, 3)
        for call in self._send.call_args_list[1:]:
            self.assertEqual(
                call[0][0].headers['x-aws-ec2-metadata-token'], 'token'
            )
        self.assertEqual(result, self._expected_creds)

    @pytest.mark.moto
    @pytest.mark.asyncio
    async def test_metadata_token_not_supported_404(self):
        user_agent = 'my-user-agent'
        self.add_imds_response(b'', status_code=404)
        self.add_get_role_name_imds_response()
        self.add_get_credentials_imds_response()

        result = await AioInstanceMetadataFetcher(
            user_agent=user_agent
        ).retrieve_iam_role_credentials()

        for call in self._send.call_args_list[1:]:
            self.assertNotIn('x-aws-ec2-metadata-token', call[0][0].headers)
        self.assertEqual(result, self._expected_creds)

    @pytest.mark.moto
    @pytest.mark.asyncio
    async def test_metadata_token_not_supported_403(self):
        user_agent = 'my-user-agent'
        self.add_imds_response(b'', status_code=403)
        self.add_get_role_name_imds_response()
        self.add_get_credentials_imds_response()

        result = await AioInstanceMetadataFetcher(
            user_agent=user_agent
        ).retrieve_iam_role_credentials()

        for call in self._send.call_args_list[1:]:
            self.assertNotIn('x-aws-ec2-metadata-token', call[0][0].headers)
        self.assertEqual(result, self._expected_creds)

    @pytest.mark.moto
    @pytest.mark.asyncio
    async def test_metadata_token_not_supported_405(self):
        user_agent = 'my-user-agent'
        self.add_imds_response(b'', status_code=405)
        self.add_get_role_name_imds_response()
        self.add_get_credentials_imds_response()

        result = await AioInstanceMetadataFetcher(
            user_agent=user_agent
        ).retrieve_iam_role_credentials()

        for call in self._send.call_args_list[1:]:
            self.assertNotIn('x-aws-ec2-metadata-token', call[0][0].headers)
        self.assertEqual(result, self._expected_creds)

    @pytest.mark.moto
    @pytest.mark.asyncio
    async def test_metadata_token_not_supported_timeout(self):
        user_agent = 'my-user-agent'
        self.add_imds_connection_error(ReadTimeoutError(endpoint_url='url'))
        self.add_get_role_name_imds_response()
        self.add_get_credentials_imds_response()

        result = await AioInstanceMetadataFetcher(
            user_agent=user_agent
        ).retrieve_iam_role_credentials()

        for call in self._send.call_args_list[1:]:
            self.assertNotIn('x-aws-ec2-metadata-token', call[0][0].headers)
        self.assertEqual(result, self._expected_creds)

    @pytest.mark.moto
    @pytest.mark.asyncio
    async def test_token_not_supported_exhaust_retries(self):
        user_agent = 'my-user-agent'
        self.add_imds_connection_error(ConnectTimeoutError(endpoint_url='url'))
        self.add_get_role_name_imds_response()
        self.add_get_credentials_imds_response()

        result = await AioInstanceMetadataFetcher(
            user_agent=user_agent
        ).retrieve_iam_role_credentials()

        for call in self._send.call_args_list[1:]:
            self.assertNotIn('x-aws-ec2-metadata-token', call[0][0].headers)
        self.assertEqual(result, self._expected_creds)

    @pytest.mark.moto
    @pytest.mark.asyncio
    async def test_metadata_token_bad_request_yields_no_credentials(self):
        user_agent = 'my-user-agent'
        self.add_imds_response(b'', status_code=400)
        result = await AioInstanceMetadataFetcher(
            user_agent=user_agent
        ).retrieve_iam_role_credentials()
        self.assertEqual(result, {})


@pytest.mark.moto
@pytest.mark.asyncio
async def test_containermetadatafetcher_retrieve_url():
    json_body = json.dumps(
        {
            "AccessKeyId": "a",
            "SecretAccessKey": "b",
            "Token": "c",
            "Expiration": "d",
        }
    )

    sleep = mock.AsyncMock()
    http = fake_aiohttp_session((json_body, 200))

    fetcher = utils.AioContainerMetadataFetcher(http, sleep)
    resp = await fetcher.retrieve_uri('/foo?id=1')
    assert resp['AccessKeyId'] == 'a'
    assert resp['SecretAccessKey'] == 'b'
    assert resp['Token'] == 'c'
    assert resp['Expiration'] == 'd'

    resp = await fetcher.retrieve_full_uri(
        'http://localhost/foo?id=1', {'extra': 'header'}
    )
    assert resp['AccessKeyId'] == 'a'
    assert resp['SecretAccessKey'] == 'b'
    assert resp['Token'] == 'c'
    assert resp['Expiration'] == 'd'


@pytest.mark.moto
@pytest.mark.asyncio
async def test_containermetadatafetcher_retrieve_url_bad_status():
    json_body = "not json"

    sleep = mock.AsyncMock()
    http = fake_aiohttp_session((json_body, 500))

    fetcher = utils.AioContainerMetadataFetcher(http, sleep)
    with pytest.raises(MetadataRetrievalError):
        await fetcher.retrieve_uri('/foo?id=1')


@pytest.mark.moto
@pytest.mark.asyncio
async def test_containermetadatafetcher_retrieve_url_not_json():
    json_body = "not json"

    sleep = mock.AsyncMock()
    http = fake_aiohttp_session((json_body, 200))

    fetcher = utils.AioContainerMetadataFetcher(http, sleep)
    with pytest.raises(MetadataRetrievalError):
        await fetcher.retrieve_uri('/foo?id=1')
