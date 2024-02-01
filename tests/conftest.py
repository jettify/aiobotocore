import asyncio
import os
import random
import string
import tempfile
from contextlib import ExitStack
from itertools import chain
from unittest.mock import patch

import httpx

# Third Party
import pytest

import aiobotocore.session
from aiobotocore.config import AioConfig
from tests._helpers import AsyncExitStack

host = '127.0.0.1'

_PYCHARM_HOSTED = os.environ.get('PYCHARM_HOSTED') == '1'


@pytest.fixture(
    scope="session", params=[True, False], ids=['debug[true]', 'debug[false]']
)
def debug(request):
    return request.param


def random_bucketname():
    # 63 is the max bucket length.
    return random_name()


def random_tablename():
    return random_name()


def random_name():
    """Return a string with presumably unique contents

    The string contains only symbols allowed for s3 buckets
    (alphanumeric, dot and hyphen).
    """
    return ''.join(random.sample(string.ascii_lowercase, k=26))


def assert_status_code(response, status_code):
    assert response['ResponseMetadata']['HTTPStatusCode'] == status_code


async def assert_num_uploads_found(
    s3_client,
    bucket_name,
    operation,
    num_uploads,
    *,
    max_items=None,
    num_attempts=5,
):
    paginator = s3_client.get_paginator(operation)
    for _ in range(num_attempts):
        pages = paginator.paginate(
            Bucket=bucket_name, PaginationConfig={'MaxItems': max_items}
        )
        responses = []
        async for page in pages:
            responses.append(page)

        # It sometimes takes a while for all the uploads to show up,
        # especially if the upload was just created.  If we don't
        # see the expected amount, we retry up to num_attempts time
        # before failing.
        amount_seen = len(responses[0]['Uploads'])
        if amount_seen == num_uploads:
            # Test passed.
            return
        else:
            # Sleep and try again.
            await asyncio.sleep(2)

        pytest.fail(
            "Expected to see {} uploads, instead saw: {}".format(
                num_uploads, amount_seen
            )
        )


@pytest.fixture
def aa_fail_proxy_config(monkeypatch):
    # NOTE: name of this fixture must be alphabetically first to run first
    monkeypatch.setenv('HTTP_PROXY', f'http://{host}:54321')
    monkeypatch.setenv('HTTPS_PROXY', f'http://{host}:54321')


@pytest.fixture
def aa_succeed_proxy_config(monkeypatch):
    # NOTE: name of this fixture must be alphabetically first to run first
    monkeypatch.setenv('HTTP_PROXY', f'http://{host}:54321')
    monkeypatch.setenv('HTTPS_PROXY', f'http://{host}:54321')

    # this will cause us to skip proxying
    monkeypatch.setenv('NO_PROXY', 'amazonaws.com')


@pytest.fixture
def session():
    session = aiobotocore.session.AioSession()
    return session


@pytest.fixture
def region():
    return 'us-east-1'


@pytest.fixture
def alternative_region():
    return 'us-west-2'


@pytest.fixture
def signature_version():
    return 's3'


@pytest.fixture
def server_scheme():
    return 'http'


@pytest.fixture
def s3_verify():
    return None


@pytest.fixture
def config(request, region, signature_version):
    config_kwargs = request.node.get_closest_marker("config_kwargs") or {}
    if config_kwargs:
        assert not config_kwargs.kwargs, config_kwargs
        assert len(config_kwargs.args) == 1
        config_kwargs = config_kwargs.args[0]

    connect_timeout = read_timout = 5
    if _PYCHARM_HOSTED:
        connect_timeout = read_timout = 180

    return AioConfig(
        region_name=region,
        signature_version=signature_version,
        read_timeout=read_timout,
        connect_timeout=connect_timeout,
        **config_kwargs,
    )


@pytest.fixture
def mocking_test():
    # change this flag for test with real aws
    # TODO: this should be merged with pytest.mark.moto
    return True


def moto_config(endpoint_url):
    kw = dict(
        endpoint_url=endpoint_url,
        aws_secret_access_key="xxx",
        aws_access_key_id="xxx",
    )

    return kw


@pytest.fixture
def patch_attributes(request):
    """Call unittest.mock.patch on arguments passed through a pytest mark.

    This fixture looks at the @pytest.mark.patch_attributes mark. This mark is a list
    of arguments to be passed to unittest.mock.patch (see example below). This fixture
    returns the list of mock objects, one per element in the input list.

    Why do we need this? In some cases, we want to perform the patching before other
    fixtures are run. For instance, the `s3_client` fixture creates an aiobotocore
    client. During the client creation process, some event listeners are registered.
    When we want to patch the target of these event listeners, we must do so before
    the `s3_client` fixture is executed.  Otherwise, the aiobotocore client will store
    references to the unpatched targets.

    In such situations, make sure that subsequent fixtures explicitly depends on
    `patch_attribute` to enforce the ordering between fixtures.

    Example:

    @pytest.mark.patch_attributes([
        dict(
            target="aiobotocore.retries.adaptive.AsyncClientRateLimiter.on_sending_request",
            side_effect=aiobotocore.retries.adaptive.AsyncClientRateLimiter.on_sending_request,
            autospec=True
        )
    ])
    async def test_client_rate_limiter_called(s3_client, patch_attributes):
        await s3_client.get_object(Bucket="bucket", Key="key")
        # Just for illustration (this test doesn't pass).
        # mock_attributes is a list of 1 element, since we passed a list of 1 element
        # to the patch_attributes marker.
        mock_attributes[0].assert_called_once()
    """
    marker = request.node.get_closest_marker("patch_attributes")
    if marker is None:
        yield
    else:
        with ExitStack() as stack:
            yield [
                stack.enter_context(patch(**kwargs))
                for kwargs in marker.args[0]
            ]


@pytest.fixture
async def s3_client(
    session,
    region,
    config,
    s3_server,
    mocking_test,
    s3_verify,
    patch_attributes,
):
    # This depends on mock_attributes because we may want to test event listeners.
    # See the documentation of `mock_attributes` for details.
    kw = moto_config(s3_server) if mocking_test else {}

    async with session.create_client(
        's3', region_name=region, config=config, verify=s3_verify, **kw
    ) as client:
        yield client


@pytest.fixture
async def alternative_s3_client(
    session, alternative_region, signature_version, s3_server, mocking_test
):
    kw = moto_config(s3_server) if mocking_test else {}

    config = AioConfig(
        region_name=alternative_region,
        signature_version=signature_version,
        read_timeout=5,
        connect_timeout=5,
    )

    async with session.create_client(
        's3', region_name=alternative_region, config=config, **kw
    ) as client:
        yield client


@pytest.fixture
async def dynamodb_client(
    session, region, config, dynamodb2_server, mocking_test
):
    kw = moto_config(dynamodb2_server) if mocking_test else {}
    async with session.create_client(
        'dynamodb', region_name=region, config=config, **kw
    ) as client:
        yield client


@pytest.fixture
async def cloudformation_client(
    session, region, config, cloudformation_server, mocking_test
):
    kw = moto_config(cloudformation_server) if mocking_test else {}
    async with session.create_client(
        'cloudformation', region_name=region, config=config, **kw
    ) as client:
        yield client


@pytest.fixture
async def sns_client(session, region, config, sns_server, mocking_test):
    kw = moto_config(sns_server) if mocking_test else {}
    async with session.create_client(
        'sns', region_name=region, config=config, **kw
    ) as client:
        yield client


@pytest.fixture
async def sqs_client(session, region, config, sqs_server, mocking_test):
    kw = moto_config(sqs_server) if mocking_test else {}
    async with session.create_client(
        'sqs', region_name=region, config=config, **kw
    ) as client:
        yield client


@pytest.fixture
async def batch_client(session, region, config, batch_server, mocking_test):
    kw = moto_config(batch_server) if mocking_test else {}
    async with session.create_client(
        'batch', region_name=region, config=config, **kw
    ) as client:
        yield client


@pytest.fixture
async def lambda_client(session, region, config, lambda_server, mocking_test):
    kw = moto_config(lambda_server) if mocking_test else {}
    async with session.create_client(
        'lambda', region_name=region, config=config, **kw
    ) as client:
        yield client


@pytest.fixture
async def iam_client(session, region, config, iam_server, mocking_test):
    kw = moto_config(iam_server) if mocking_test else {}
    async with session.create_client(
        'iam', region_name=region, config=config, **kw
    ) as client:
        yield client


@pytest.fixture
async def rds_client(session, region, config, rds_server, mocking_test):
    kw = moto_config(rds_server) if mocking_test else {}
    async with session.create_client(
        'rds', region_name=region, config=config, **kw
    ) as client:
        yield client


@pytest.fixture
async def ec2_client(session, region, config, ec2_server, mocking_test):
    kw = moto_config(ec2_server) if mocking_test else {}
    async with session.create_client(
        'ec2', region_name=region, config=config, **kw
    ) as client:
        yield client


@pytest.fixture
async def kinesis_client(
    session, region, config, kinesis_server, mocking_test
):
    kw = moto_config(kinesis_server) if mocking_test else {}
    async with session.create_client(
        'kinesis', region_name=region, config=config, **kw
    ) as client:
        yield client


async def recursive_delete(s3_client, bucket_name):
    # Recursively deletes a bucket and all of its contents.
    paginator = s3_client.get_paginator('list_object_versions')
    async for n in paginator.paginate(Bucket=bucket_name, Prefix=''):
        for obj in chain(
            n.get('Versions', []),
            n.get('DeleteMarkers', []),
            n.get('Contents', []),
            n.get('CommonPrefixes', []),
        ):
            kwargs = dict(Bucket=bucket_name, Key=obj['Key'])
            if 'VersionId' in obj:
                kwargs['VersionId'] = obj['VersionId']
            resp = await s3_client.delete_object(**kwargs)
            assert_status_code(resp, 204)

    resp = await s3_client.delete_bucket(Bucket=bucket_name)
    assert_status_code(resp, 204)


@pytest.fixture
async def bucket_name(region, create_bucket):
    name = await create_bucket(region)
    yield name


@pytest.fixture
async def table_name(create_table):
    name = await create_table()
    yield name


@pytest.fixture
async def create_bucket(s3_client):
    _bucket_name = None

    async def _f(region_name, bucket_name=None):
        nonlocal _bucket_name
        if bucket_name is None:
            bucket_name = random_bucketname()
        _bucket_name = bucket_name
        bucket_kwargs = {'Bucket': bucket_name}
        if region_name != 'us-east-1':
            bucket_kwargs['CreateBucketConfiguration'] = {
                'LocationConstraint': region_name,
            }
        response = await s3_client.create_bucket(**bucket_kwargs)
        assert_status_code(response, 200)
        await s3_client.put_bucket_versioning(
            Bucket=bucket_name, VersioningConfiguration={'Status': 'Enabled'}
        )
        return bucket_name

    try:
        yield _f
    finally:
        await recursive_delete(s3_client, _bucket_name)


@pytest.fixture
async def create_table(dynamodb_client):
    _table_name = None

    async def _is_table_ready(table_name):
        response = await dynamodb_client.describe_table(TableName=table_name)
        return response['Table']['TableStatus'] == 'ACTIVE'

    async def _f(table_name=None):
        nonlocal _table_name
        if table_name is None:
            table_name = random_tablename()
        _table_name = table_name
        table_kwargs = {
            'TableName': table_name,
            'AttributeDefinitions': [
                {'AttributeName': 'testKey', 'AttributeType': 'S'},
            ],
            'KeySchema': [
                {'AttributeName': 'testKey', 'KeyType': 'HASH'},
            ],
            'ProvisionedThroughput': {
                'ReadCapacityUnits': 1,
                'WriteCapacityUnits': 1,
            },
        }

        response = await dynamodb_client.create_table(**table_kwargs)
        while not (await _is_table_ready(table_name)):
            pass

        assert_status_code(response, 200)
        return table_name

    try:
        yield _f
    finally:
        await delete_table(dynamodb_client, _table_name)


async def delete_table(dynamodb_client, table_name):
    response = await dynamodb_client.delete_table(TableName=table_name)
    assert_status_code(response, 200)


@pytest.fixture
def tempdir():
    with tempfile.TemporaryDirectory() as td:
        yield td


@pytest.fixture
def create_object(s3_client, bucket_name):
    async def _f(key_name, body='foo'):
        r = await s3_client.put_object(
            Bucket=bucket_name, Key=key_name, Body=body
        )
        assert_status_code(r, 200)
        return r

    return _f


@pytest.fixture
def create_multipart_upload(request, s3_client, bucket_name, event_loop):
    _key_name = None
    upload_id = None

    async def _f(key_name):
        nonlocal _key_name
        nonlocal upload_id
        _key_name = key_name

        parsed = await s3_client.create_multipart_upload(
            Bucket=bucket_name, Key=key_name
        )
        upload_id = parsed['UploadId']
        return upload_id

    def fin():
        event_loop.run_until_complete(
            s3_client.abort_multipart_upload(
                UploadId=upload_id, Bucket=bucket_name, Key=_key_name
            )
        )

    request.addfinalizer(fin)
    return _f


@pytest.fixture
async def httpx_async_client():
    async with httpx.AsyncClient() as client:
        yield client


def pytest_configure():
    class AIOUtils:
        def __init__(self):
            self.assert_status_code = assert_status_code
            self.assert_num_uploads_found = assert_num_uploads_found

    pytest.aio = AIOUtils()


@pytest.fixture
def dynamodb_put_item(dynamodb_client, table_name):
    async def _f(key_string_value):
        response = await dynamodb_client.put_item(
            TableName=table_name,
            Item={'testKey': {'S': key_string_value}},
        )
        assert_status_code(response, 200)

    return _f


@pytest.fixture
def topic_arn(region, create_topic, sns_client, event_loop):
    arn = event_loop.run_until_complete(create_topic())
    return arn


async def delete_topic(sns_client, topic_arn):
    response = await sns_client.delete_topic(TopicArn=topic_arn)
    assert_status_code(response, 200)


@pytest.fixture
def create_topic(request, sns_client, event_loop):
    _topic_arn = None

    async def _f():
        nonlocal _topic_arn
        response = await sns_client.create_topic(Name=random_name())
        _topic_arn = response['TopicArn']
        assert_status_code(response, 200)
        return _topic_arn

    def fin():
        event_loop.run_until_complete(delete_topic(sns_client, _topic_arn))

    request.addfinalizer(fin)
    return _f


@pytest.fixture
async def sqs_queue_url(sqs_client):
    response = await sqs_client.create_queue(QueueName=random_name())
    queue_url = response['QueueUrl']
    assert_status_code(response, 200)

    try:
        yield queue_url
    finally:
        response = await sqs_client.delete_queue(QueueUrl=queue_url)
        assert_status_code(response, 200)


@pytest.fixture
async def exit_stack():
    async with AsyncExitStack() as es:
        yield es


pytest_plugins = ['tests.mock_server']
