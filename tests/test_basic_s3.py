import asyncio
import base64
import hashlib
from collections import defaultdict
from typing import Callable

import aioitertools
import botocore.retries.adaptive
import httpx
import pytest

import aiobotocore.retries.adaptive
from aiobotocore import httpsession


async def fetch_all(pages):
    responses = []
    async for n in pages:
        responses.append(n)
    return responses


@pytest.mark.moto
@pytest.mark.asyncio
async def test_can_make_request(s3_client):
    # Basic smoke test to ensure we can talk to s3.
    result = await s3_client.list_buckets()
    # Can't really assume anything about whether or not they have buckets,
    # but we can assume something about the structure of the response.
    actual_keys = sorted(list(result.keys()))
    assert actual_keys == ['Buckets', 'Owner', 'ResponseMetadata']


@pytest.mark.moto
@pytest.mark.parametrize('s3_verify', [False])
@pytest.mark.asyncio
async def test_can_make_request_no_verify(s3_client):
    # Basic smoke test to ensure we can talk to s3.
    result = await s3_client.list_buckets()
    # Can't really assume anything about whether or not they have buckets,
    # but we can assume something about the structure of the response.
    actual_keys = sorted(list(result.keys()))
    assert actual_keys == ['Buckets', 'Owner', 'ResponseMetadata']


@pytest.mark.moto
@pytest.mark.asyncio
async def test_fail_proxy_request(
    aa_fail_proxy_config, s3_client, monkeypatch
):
    # based on test_can_make_request
    with pytest.raises(httpsession.ProxyConnectionError):
        await s3_client.list_buckets()


@pytest.mark.asyncio
@pytest.mark.parametrize('mocking_test', [False])
async def test_succeed_proxy_request(aa_succeed_proxy_config, s3_client):
    result = await s3_client.list_buckets()
    actual_keys = sorted(list(result.keys()))
    assert actual_keys == ['Buckets', 'Owner', 'ResponseMetadata']


@pytest.mark.asyncio
@pytest.mark.moto
async def test_can_get_bucket_location(s3_client, bucket_name):
    result = await s3_client.get_bucket_location(Bucket=bucket_name)
    assert 'LocationConstraint' in result
    # For buckets in us-east-1 (US Classic Region) this will be None
    # TODO fix this
    assert result['LocationConstraint'] in [None, 'us-west-2', 'us-east-1']


@pytest.mark.moto
@pytest.mark.asyncio
async def test_can_delete_urlencoded_object(
    s3_client, bucket_name, create_object
):
    key_name = 'a+b/foo'
    await create_object(key_name=key_name)
    resp = await s3_client.list_objects(Bucket=bucket_name)
    bucket_contents = resp['Contents']
    assert len(bucket_contents) == 1
    assert bucket_contents[-1]['Key'] == 'a+b/foo'

    # TODO: unfortunately this is broken now: https://github.com/spulec/moto/issues/5030
    # resp = await s3_client.list_objects(Bucket=bucket_name, Prefix='a+b')
    # subdir_contents = resp['Contents']
    # assert len(subdir_contents) == 1
    # assert subdir_contents[0]['Key'] == 'a+b/foo'

    response = await s3_client.delete_object(Bucket=bucket_name, Key=key_name)
    pytest.aio.assert_status_code(response, 204)


@pytest.mark.asyncio
@pytest.mark.moto
async def test_can_paginate(s3_client, bucket_name, create_object):
    for i in range(5):
        key_name = 'key%s' % i
        await create_object(key_name)

    paginator = s3_client.get_paginator('list_objects')
    pages = paginator.paginate(MaxKeys=1, Bucket=bucket_name)
    responses = await fetch_all(pages)

    assert len(responses) == 5, responses
    key_names = [el['Contents'][0]['Key'] for el in responses]
    assert key_names == ['key0', 'key1', 'key2', 'key3', 'key4']


@pytest.mark.asyncio
@pytest.mark.moto
async def test_can_paginate_with_page_size(
    s3_client, bucket_name, create_object
):
    for i in range(5):
        key_name = 'key%s' % i
        await create_object(key_name)

    paginator = s3_client.get_paginator('list_objects')
    pages = paginator.paginate(
        PaginationConfig={'PageSize': 1}, Bucket=bucket_name
    )

    responses = await fetch_all(pages)
    assert len(responses) == 5, responses
    data = [r for r in responses]
    key_names = [el['Contents'][0]['Key'] for el in data]
    assert key_names == ['key0', 'key1', 'key2', 'key3', 'key4']


@pytest.mark.asyncio
@pytest.mark.moto
async def test_can_search_paginate(s3_client, bucket_name, create_object):
    keys = []
    for i in range(5):
        key_name = 'key%s' % i
        keys.append(key_name)
        await create_object(key_name)

    paginator = s3_client.get_paginator('list_objects')
    page_iter = paginator.paginate(Bucket=bucket_name)
    async for key_name in page_iter.search('Contents[*].Key'):
        assert key_name in keys


@pytest.mark.asyncio
@pytest.mark.moto
async def test_can_paginate_iterator(s3_client, bucket_name, create_object):
    for i in range(5):
        key_name = 'key%s' % i
        await create_object(key_name)

    paginator = s3_client.get_paginator('list_objects')
    responses = []
    async for page in paginator.paginate(
        PaginationConfig={'PageSize': 1}, Bucket=bucket_name
    ):
        assert not asyncio.iscoroutine(page)
        responses.append(page)
    assert len(responses) == 5, responses
    data = [r for r in responses]
    key_names = [el['Contents'][0]['Key'] for el in data]
    assert key_names == ['key0', 'key1', 'key2', 'key3', 'key4']


@pytest.mark.asyncio
@pytest.mark.moto
async def test_result_key_iters(s3_client, bucket_name, create_object):
    for i in range(5):
        key_name = f'key/{i}/{i}'
        await create_object(key_name)
        key_name2 = 'key/%s' % i
        await create_object(key_name2)

    paginator = s3_client.get_paginator('list_objects')
    generator = paginator.paginate(
        MaxKeys=2, Prefix='key/', Delimiter='/', Bucket=bucket_name
    )
    iterators = generator.result_key_iters()
    response = defaultdict(list)
    key_names = [i.result_key for i in iterators]

    # adapt to aioitertools ideas
    iterators = [itr.__aiter__() for itr in iterators]

    async for vals in aioitertools.zip_longest(*iterators):
        pass

        for k, val in zip(key_names, vals):
            response.setdefault(k.expression, [])
            response[k.expression].append(val)

    assert 'Contents' in response
    assert 'CommonPrefixes' in response


@pytest.mark.moto
@pytest.mark.asyncio
async def test_can_get_and_put_object(
    s3_client: aiobotocore.client.AioBaseClient,
    create_object: Callable,
    bucket_name: object,
):
    await create_object('foobarbaz', body='body contents')
    resp = await s3_client.get_object(Bucket=bucket_name, Key='foobarbaz')
    if isinstance(resp['Body'], httpx.Response):
        data = await resp['Body'].aread()
        # note that calling `aclose()` is redundant, httpx will auto-close when the
        # data is fully read
        await resp['Body'].aclose()
    else:
        data = await resp['Body'].read()
        resp['Body'].close()
    assert data == b'body contents'


@pytest.mark.moto
@pytest.mark.asyncio
@pytest.mark.patch_attributes(
    [
        dict(
            target="aiobotocore.retries.adaptive.AsyncClientRateLimiter.on_sending_request",
            side_effect=aiobotocore.retries.adaptive.AsyncClientRateLimiter.on_sending_request,
            autospec=True,
        ),
        dict(
            target="aiobotocore.retries.adaptive.AsyncClientRateLimiter.on_receiving_response",
            side_effect=aiobotocore.retries.adaptive.AsyncClientRateLimiter.on_receiving_response,
            autospec=True,
        ),
        dict(
            target="botocore.retries.adaptive.ClientRateLimiter.on_sending_request",
            side_effect=botocore.retries.adaptive.ClientRateLimiter.on_sending_request,
            autospec=True,
        ),
        dict(
            target="botocore.retries.adaptive.ClientRateLimiter.on_receiving_response",
            side_effect=botocore.retries.adaptive.ClientRateLimiter.on_receiving_response,
            autospec=True,
        ),
    ]
)
@pytest.mark.config_kwargs(
    dict(retries={"max_attempts": 5, "mode": "adaptive"})
)
async def test_adaptive_retry(
    s3_client, config, create_object, bucket_name, patch_attributes
):
    await create_object('foobarbaz', body='body contents')

    # Check that our async implementations were correctly called.
    # We need to patch event listeners before the S3 client is created (see
    # documentation for `patch_attributes`), but as a result, other calls may be
    # performed during the setup of other fixtures. Thus, we can't rely on the total
    # number of calls, we just inspect the last one.
    assert len(patch_attributes[0].mock_calls) > 0  # on_sending_request
    _, _, call_args = patch_attributes[0].mock_calls[-1]
    assert call_args["event_name"] == "before-send.s3.PutObject"
    assert call_args["request"].url.endswith("foobarbaz")

    assert len(patch_attributes[1].mock_calls) > 0  # on_receiving_response
    _, _, call_args = patch_attributes[1].mock_calls[-1]
    assert call_args["event_name"] == "needs-retry.s3.PutObject"

    # Check that we did not call any blocking method.
    # Unfortunately can't directly patch threading.Lock.__enter__.
    patch_attributes[2].assert_not_called()
    patch_attributes[3].assert_not_called()


@pytest.mark.moto
@pytest.mark.asyncio
async def test_get_object_stream_wrapper(
    s3_client, create_object, bucket_name
):
    await create_object('foobarbaz', body='body contents')
    response = await s3_client.get_object(Bucket=bucket_name, Key='foobarbaz')
    body = response['Body']
    if isinstance(body, httpx.Response):
        byte_iterator = body.aiter_raw(1)
        chunk1 = await anext(byte_iterator)
        chunk2 = b""
        async for b in byte_iterator:
            chunk2 += b
        await body.aclose()
    else:
        chunk1 = await body.read(1)
        chunk2 = await body.read()
        body.close()
    assert chunk1 == b'b'
    assert chunk2 == b'ody contents'


@pytest.mark.moto
@pytest.mark.asyncio
async def test_get_object_stream_context(
    s3_client, create_object, bucket_name
):
    await create_object('foobarbaz', body='body contents')
    response = await s3_client.get_object(Bucket=bucket_name, Key='foobarbaz')
    # httpx does not support context manager
    if isinstance(response['Body'], httpx.Response):
        data = await response['Body'].aread()
    else:
        async with response['Body'] as stream:
            data = await stream.read()
    assert data == b'body contents'


@pytest.mark.asyncio
@pytest.mark.moto
async def test_paginate_max_items(
    s3_client, create_multipart_upload, bucket_name
):
    await create_multipart_upload('foo/key1')
    await create_multipart_upload('foo/key1')
    await create_multipart_upload('foo/key1')
    await create_multipart_upload('foo/key2')
    await create_multipart_upload('foobar/key1')
    await create_multipart_upload('foobar/key2')
    await create_multipart_upload('bar/key1')
    await create_multipart_upload('bar/key2')

    # Verify when we have MaxItems=None, we get back all 8 uploads.
    await pytest.aio.assert_num_uploads_found(
        s3_client,
        bucket_name,
        'list_multipart_uploads',
        max_items=None,
        num_uploads=8,
    )

    # Verify when we have MaxItems=1, we get back 1 upload.
    await pytest.aio.assert_num_uploads_found(
        s3_client,
        bucket_name,
        'list_multipart_uploads',
        max_items=1,
        num_uploads=1,
    )

    paginator = s3_client.get_paginator('list_multipart_uploads')
    # Works similar with build_full_result()
    pages = paginator.paginate(
        PaginationConfig={'MaxItems': 1}, Bucket=bucket_name
    )
    full_result = await pages.build_full_result()
    assert len(full_result['Uploads']) == 1


@pytest.mark.moto
@pytest.mark.asyncio
async def test_paginate_within_page_boundaries(
    s3_client, create_object, bucket_name
):
    await create_object('a')
    await create_object('b')
    await create_object('c')
    await create_object('d')
    paginator = s3_client.get_paginator('list_objects')
    # First do it without a max keys so we're operating on a single page of
    # results.
    pages = paginator.paginate(
        PaginationConfig={'MaxItems': 1}, Bucket=bucket_name
    )
    first = await pages.build_full_result()
    t1 = first['NextToken']

    pages = paginator.paginate(
        PaginationConfig={'MaxItems': 1, 'StartingToken': t1},
        Bucket=bucket_name,
    )
    second = await pages.build_full_result()
    t2 = second['NextToken']

    pages = paginator.paginate(
        PaginationConfig={'MaxItems': 1, 'StartingToken': t2},
        Bucket=bucket_name,
    )
    third = await pages.build_full_result()
    t3 = third['NextToken']

    pages = paginator.paginate(
        PaginationConfig={'MaxItems': 1, 'StartingToken': t3},
        Bucket=bucket_name,
    )
    fourth = await pages.build_full_result()

    assert first['Contents'][-1]['Key'] == 'a'
    assert second['Contents'][-1]['Key'] == 'b'
    assert third['Contents'][-1]['Key'] == 'c'
    assert fourth['Contents'][-1]['Key'] == 'd'


@pytest.mark.asyncio
@pytest.mark.parametrize('mocking_test', [False])
async def test_unicode_key_put_list(s3_client, bucket_name, create_object):
    # Verify we can upload a key with a unicode char and list it as well.
    key_name = '\u2713'
    await create_object(key_name)
    parsed = await s3_client.list_objects(Bucket=bucket_name)
    assert len(parsed['Contents']) == 1
    assert parsed['Contents'][0]['Key'] == key_name
    parsed = await s3_client.get_object(Bucket=bucket_name, Key=key_name)
    if isinstance(parsed['Body'], httpx.Response):
        data = await parsed['Body'].aread()
        await parsed['Body'].aclose()
    else:
        data = await parsed['Body'].read()
        parsed['Body'].close()
    assert data == b'foo'


@pytest.mark.asyncio
@pytest.mark.parametrize('mocking_test', [False])
async def test_unicode_system_character(s3_client, bucket_name, create_object):
    # Verify we can use a unicode system character which would normally
    # break the xml parser
    key_name = 'foo\x08'
    await create_object(key_name)
    parsed = await s3_client.list_objects(Bucket=bucket_name)
    assert len(parsed['Contents']) == 1
    assert parsed['Contents'][0]['Key'] == key_name

    parsed = await s3_client.list_objects(
        Bucket=bucket_name, EncodingType='url'
    )
    assert len(parsed['Contents']) == 1
    assert parsed['Contents'][0]['Key'] == 'foo%08'


@pytest.mark.moto
@pytest.mark.asyncio
async def test_non_normalized_key_paths(s3_client, bucket_name, create_object):
    # The create_object method has assertEqual checks for 200 status.
    await create_object('key./././name')
    bucket = await s3_client.list_objects(Bucket=bucket_name)
    bucket_contents = bucket['Contents']
    assert len(bucket_contents) == 1
    assert bucket_contents[0]['Key'] == 'key./././name'


@pytest.mark.skipif(True, reason='Not supported')
@pytest.mark.asyncio
async def test_reset_stream_on_redirects(region, create_bucket):
    # Create a bucket in a non classic region.
    bucket_name = await create_bucket(region)
    # Then try to put a file like object to this location.
    assert bucket_name


@pytest.mark.moto
@pytest.mark.asyncio
async def test_copy_with_quoted_char(s3_client, create_object, bucket_name):
    key_name = 'a+b/foo'
    await create_object(key_name=key_name)

    key_name2 = key_name + 'bar'
    source = f'{bucket_name}/{key_name}'
    await s3_client.copy_object(
        Bucket=bucket_name, Key=key_name2, CopySource=source
    )

    # Now verify we can retrieve the copied object.
    resp = await s3_client.get_object(Bucket=bucket_name, Key=key_name2)
    if isinstance(resp['Body'], httpx.Response):
        data = await resp['Body'].aread()
        await resp['Body'].aclose()
    else:
        data = await resp['Body'].read()
        resp['Body'].close()
    assert data == b'foo'


@pytest.mark.moto
@pytest.mark.asyncio
async def test_copy_with_query_string(s3_client, create_object, bucket_name):
    key_name = 'a+b/foo?notVersionid=bar'
    await create_object(key_name=key_name)

    key_name2 = key_name + 'bar'
    await s3_client.copy_object(
        Bucket=bucket_name,
        Key=key_name2,
        CopySource=f'{bucket_name}/{key_name}',
    )

    # Now verify we can retrieve the copied object.
    resp = await s3_client.get_object(Bucket=bucket_name, Key=key_name2)
    if isinstance(resp['Body'], httpx.Response):
        data = await resp['Body'].aread()
        await resp['Body'].aclose()
    else:
        data = await resp['Body'].read()
        resp['Body'].close()
    assert data == b'foo'


@pytest.mark.moto
@pytest.mark.asyncio
async def test_can_copy_with_dict_form(s3_client, create_object, bucket_name):
    key_name = 'a+b/foo?versionId=abcd'
    await create_object(key_name=key_name)

    key_name2 = key_name + 'bar'
    await s3_client.copy_object(
        Bucket=bucket_name,
        Key=key_name2,
        CopySource={'Bucket': bucket_name, 'Key': key_name},
    )

    # Now verify we can retrieve the copied object.
    resp = await s3_client.get_object(Bucket=bucket_name, Key=key_name2)
    if isinstance(resp['Body'], httpx.Response):
        data = await resp['Body'].aread()
        await resp['Body'].aclose()
    else:
        data = await resp['Body'].read()
        resp['Body'].close()
    assert data == b'foo'


@pytest.mark.moto
@pytest.mark.asyncio
async def test_can_copy_with_dict_form_with_version(
    s3_client, create_object, bucket_name
):
    key_name = 'a+b/foo?versionId=abcd'
    response = await create_object(key_name=key_name)
    key_name2 = key_name + 'bar'
    await s3_client.copy_object(
        Bucket=bucket_name,
        Key=key_name2,
        CopySource={
            'Bucket': bucket_name,
            'Key': key_name,
            'VersionId': response["VersionId"],
        },
    )

    # Now verify we can retrieve the copied object.
    resp = await s3_client.get_object(Bucket=bucket_name, Key=key_name2)
    if isinstance(resp['Body'], httpx.Response):
        data = await resp['Body'].aread()
        await resp['Body'].aclose()
    else:
        data = await resp['Body'].read()
        resp['Body'].close()
    assert data == b'foo'


@pytest.mark.moto
@pytest.mark.asyncio
async def test_copy_with_s3_metadata(s3_client, create_object, bucket_name):
    key_name = 'foo.txt'
    await create_object(key_name=key_name)
    copied_key = 'copied.txt'
    parsed = await s3_client.copy_object(
        Bucket=bucket_name,
        Key=copied_key,
        CopySource=f'{bucket_name}/{key_name}',
        MetadataDirective='REPLACE',
        Metadata={"mykey": "myvalue", "mykey2": "myvalue2"},
    )
    pytest.aio.assert_status_code(parsed, 200)


@pytest.mark.parametrize('region', ['us-east-1'])
@pytest.mark.parametrize('signature_version', ['s3'])
# 'Content-Disposition' not supported by moto yet
@pytest.mark.parametrize('mocking_test', [False])
@pytest.mark.asyncio
async def test_presign_with_existing_query_string_values(
    s3_client, bucket_name, aio_session, create_object
):
    key_name = 'foo.txt'
    await create_object(key_name=key_name)
    content_disposition = 'attachment; filename=foo.txt;'
    params = {
        'Bucket': bucket_name,
        'Key': key_name,
        'ResponseContentDisposition': content_disposition,
    }
    presigned_url = await s3_client.generate_presigned_url(
        'get_object', Params=params
    )
    # Try to retrieve the object using the presigned url.
    if isinstance(aio_session, httpx.AsyncClient):
        async with aio_session.stream("GET", presigned_url) as resp:
            data = await resp.aread()
            headers = resp.headers
    else:
        async with aio_session.get(presigned_url) as resp:
            data = await resp.read()
            headers = resp.headers
    assert headers['Content-Disposition'] == content_disposition
    assert data == b'foo'


@pytest.mark.parametrize('region', ['us-east-1'])
@pytest.mark.parametrize('signature_version', ['s3v4'])
# moto host will be localhost
@pytest.mark.parametrize('mocking_test', [False])
@pytest.mark.asyncio
async def test_presign_sigv4(
    s3_client, bucket_name, aio_session, create_object
):
    key = 'myobject'
    await create_object(key_name=key)
    presigned_url = await s3_client.generate_presigned_url(
        'get_object', Params={'Bucket': bucket_name, 'Key': key}
    )
    msg = (
        "Host was suppose to be the us-east-1 endpoint, "
        "instead got: %s" % presigned_url
    )
    assert presigned_url.startswith(
        f'https://{bucket_name}.s3.amazonaws.com/{key}'
    ), msg

    # Try to retrieve the object using the presigned url.
    if isinstance(aio_session, httpx.AsyncClient):
        async with aio_session.stream("GET", presigned_url) as resp:
            data = await resp.aread()
    else:
        async with aio_session.get(presigned_url) as resp:
            data = await resp.read()
    assert data == b'foo'


@pytest.mark.parametrize('signature_version', ['s3v4'])
@pytest.mark.parametrize('mocking_test', [False])
@pytest.mark.asyncio
async def test_can_follow_signed_url_redirect(
    alternative_s3_client, create_object, bucket_name
):
    await create_object('foobarbaz')

    # Simulate redirection by provide wrong endpoint intentionally
    resp = await alternative_s3_client.get_object(
        Bucket=bucket_name, Key='foobarbaz'
    )
    if isinstance(resp['Body'], httpx.Response):
        data = await resp['Body'].aread()
        await resp['Body'].aclose()
    else:
        data = await resp['Body'].read()
        resp['Body'].close()
    assert data == b'foo'


@pytest.mark.parametrize('region', ['eu-west-1'])
@pytest.mark.parametrize('alternative_region', ['us-west-2'])
@pytest.mark.parametrize('mocking_test', [False])
@pytest.mark.asyncio
async def test_bucket_redirect(
    s3_client, alternative_s3_client, region, create_bucket
):
    key = 'foobarbaz'

    # create bucket in alternative region
    bucket_name = await create_bucket(region)

    await s3_client.put_object(Bucket=bucket_name, Key=key, Body=b'')
    await s3_client.get_object(Bucket=bucket_name, Key=key)

    # This should not raise
    await alternative_s3_client.put_object(
        Bucket=bucket_name, Key=key, Body=b''
    )
    await alternative_s3_client.get_object(Bucket=bucket_name, Key=key)


@pytest.mark.parametrize('signature_version', ['s3v4'])
@pytest.mark.asyncio
@pytest.mark.moto
async def test_head_object_keys(s3_client, create_object, bucket_name):
    await create_object('foobarbaz')

    resp = await s3_client.head_object(Bucket=bucket_name, Key='foobarbaz')

    # this is to ensure things like:
    # https://github.com/aio-libs/aiobotocore/issues/131 don't happen again
    assert set(resp.keys()) == {
        'AcceptRanges',
        'ETag',
        'ContentType',
        'Metadata',
        'LastModified',
        'ResponseMetadata',
        'ContentLength',
        'VersionId',
    }


@pytest.mark.xfail(
    reason="moto does not yet support Checksum: https://github.com/spulec/moto/issues/5719"
)
@pytest.mark.parametrize('server_scheme', ['https'])
@pytest.mark.parametrize('s3_verify', [False])
@pytest.mark.moto
@pytest.mark.asyncio
async def test_put_object_sha256(s3_client, bucket_name):
    data = b'test1234'
    digest = hashlib.sha256(data).digest().hex()

    resp = await s3_client.put_object(
        Bucket=bucket_name,
        Key='foobarbaz',
        Body=data,
        ChecksumAlgorithm='SHA256',
    )
    sha256_trailer_checksum = base64.b64decode(resp['ChecksumSHA256'])

    assert digest == sha256_trailer_checksum
