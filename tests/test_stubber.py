import pytest

from aiobotocore.awsrequest import AioAWSResponse
from aiobotocore.session import AioSession
from aiobotocore.stub import AioStubber

from .mock_server import AIOServer

# these tests don't currently care about aiohttp vs httpx


@pytest.mark.moto
@pytest.mark.asyncio
async def test_add_response():
    session = AioSession()

    async with AIOServer() as server, session.create_client(
        's3',
        endpoint_url=server.endpoint_url,
        aws_secret_access_key='xxx',
        aws_access_key_id='xxx',
    ) as s3_client:
        stubber = AioStubber(s3_client)
        operation_name = 'put_object'
        service_response = dict(
            ETag="6805f2cfc46c0f04559748bb039d69ae",
            VersionId="psM2sYY4.o1501dSx8wMvnkOzSBB.V4a",
        )
        expected_params = dict()
        stubber.add_response(operation_name, service_response, expected_params)

        assert len(stubber._queue) == 1
        assert stubber._queue[0][
            'operation_name'
        ] == s3_client.meta.method_to_api_mapping.get(operation_name)
        assert isinstance(stubber._queue[0]['response'][0], AioAWSResponse)
        assert stubber._queue[0]['response'][1] == service_response
        assert stubber._queue[0]['expected_params'] == expected_params


@pytest.mark.moto
@pytest.mark.asyncio
async def test_add_client_error():
    session = AioSession()

    async with AIOServer() as server, session.create_client(
        's3',
        endpoint_url=server.endpoint_url,
        aws_secret_access_key='xxx',
        aws_access_key_id='xxx',
    ) as s3_client:
        stubber = AioStubber(s3_client)
        operation_name = 'put_object'
        service_error_code = 'InvalidObjectState'
        service_message = 'Object is in invalid state'
        http_status_code = 400
        service_error_meta = {"AdditionalInfo": "value"}
        response_meta = {"AdditionalResponseInfo": "value"}
        modeled_fields = {'StorageClass': 'foo', 'AccessTier': 'bar'}

        stubber.add_client_error(
            operation_name,
            service_error_code,
            service_message,
            http_status_code,
            service_error_meta,
            response_meta=response_meta,
            modeled_fields=modeled_fields,
        )

        assert len(stubber._queue) == 1
        assert stubber._queue[0][
            'operation_name'
        ] == s3_client.meta.method_to_api_mapping.get(operation_name)
        assert isinstance(stubber._queue[0]['response'][0], AioAWSResponse)
        assert stubber._queue[0]['response'][1]
