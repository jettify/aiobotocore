import asyncio

import aiohttp.resolver
import pytest
from botocore.config import Config
from botocore.exceptions import ParamValidationError, ReadTimeoutError

from aiobotocore.config import AioConfig
from aiobotocore.httpsession import HttpxSession
from aiobotocore.session import AioSession, get_session
from tests.mock_server import AIOServer


# NOTE: this doesn't require moto but needs to be marked to run with coverage
@pytest.mark.moto
@pytest.mark.asyncio
async def test_connector_args(current_http_backend: str):
    with pytest.raises(ParamValidationError):
        # wrong type
        connector_args: dict[str, object] = dict(use_dns_cache=1)
        AioConfig(connector_args)

    with pytest.raises(ParamValidationError):
        # wrong type
        connector_args = dict(keepalive_timeout="1")
        AioConfig(connector_args)

    with pytest.raises(ParamValidationError):
        # wrong type
        connector_args = dict(force_close="1")
        AioConfig(connector_args)

    with pytest.raises(ParamValidationError):
        # wrong type
        connector_args = dict(keepalive_timeout="1")
        AioConfig(connector_args)

    with pytest.raises(ParamValidationError):
        # wrong type
        connector_args = dict(ssl_context="1")
        AioConfig(connector_args)

    with pytest.raises(ParamValidationError):
        # invalid DNS resolver
        connector_args = dict(resolver="1")
        AioConfig(connector_args)

    with pytest.raises(ParamValidationError):
        # invalid key
        connector_args = dict(foo="1")
        AioConfig(connector_args)

    with pytest.raises(
        ParamValidationError,
        match='Httpx does not support dns caching. https://github.com/encode/httpx/discussions/2211',
    ):
        AioConfig({'use_dns_cache': True}, http_session_cls=HttpxSession)

    with pytest.raises(
        ParamValidationError,
        match='Httpx backend does not currently support force_close.',
    ):
        AioConfig({'force_close': True}, http_session_cls=HttpxSession)

    with pytest.raises(
        ParamValidationError, match='Httpx backend does not support resolver.'
    ):
        AioConfig({'resolver': True}, http_session_cls=HttpxSession)

    # Test valid configs:
    AioConfig({"resolver": aiohttp.resolver.DefaultResolver()})
    AioConfig({'keepalive_timeout': None})

    # test merge
    cfg = Config(read_timeout=75)
    aio_cfg = AioConfig({'keepalive_timeout': 75})
    aio_cfg.merge(cfg)

    assert cfg.read_timeout == 75
    assert aio_cfg.connector_args['keepalive_timeout'] == 75


@pytest.mark.moto
@pytest.mark.asyncio
async def test_connector_timeout():
    session = AioSession()
    config = AioConfig(
        max_pool_connections=1, connect_timeout=1, retries={'max_attempts': 0}
    )
    async with AIOServer() as server, session.create_client(
        's3',
        config=config,
        endpoint_url=server.endpoint_url,
        aws_secret_access_key='xxx',
        aws_access_key_id='xxx',
    ) as s3_client:

        async def get_and_wait():
            await s3_client.get_object(Bucket='foo', Key='bar')
            await asyncio.sleep(100)

        task1 = asyncio.Task(get_and_wait())
        task2 = asyncio.Task(get_and_wait())

        try:
            done, pending = await asyncio.wait([task1, task2], timeout=3)

            # second request should not timeout just because there isn't a
            # connector available
            assert len(pending) == 2
        finally:
            task1.cancel()
            task2.cancel()


@pytest.mark.moto
@pytest.mark.asyncio
async def test_connector_timeout2():
    session = AioSession()
    config = AioConfig(
        max_pool_connections=1,
        connect_timeout=1,
        read_timeout=1,
        retries={'max_attempts': 0},
    )
    async with AIOServer() as server, session.create_client(
        's3',
        config=config,
        endpoint_url=server.endpoint_url,
        aws_secret_access_key='xxx',
        aws_access_key_id='xxx',
    ) as s3_client:
        with pytest.raises(ReadTimeoutError):
            resp = await s3_client.get_object(Bucket='foo', Key='bar')
            await resp["Body"].read()


@pytest.mark.moto
@pytest.mark.asyncio
async def test_get_session():
    session = get_session()
    assert isinstance(session, AioSession)


@pytest.mark.moto
def test_merge():
    config = AioConfig()
    other_config = AioConfig()
    new_config = config.merge(other_config)
    assert isinstance(new_config, AioConfig)
    assert new_config is not config
    assert new_config is not other_config
