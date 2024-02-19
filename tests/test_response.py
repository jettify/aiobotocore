import io

import pytest
from botocore.exceptions import IncompleteReadError

from aiobotocore import response


# https://github.com/boto/botocore/blob/develop/tests/unit/test_response.py
async def assert_lines(line_iterator, expected_lines):
    for expected_line in expected_lines:
        line = await line_iterator.__anext__()
        assert line == expected_line

    # We should have exhausted the iterator.
    with pytest.raises(StopAsyncIteration):
        await line_iterator.__anext__()


class AsyncBytesIO(io.BytesIO):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.content = self

    async def read(self, amt=-1):
        if amt == -1:  # aiohttp to regular response
            amt = None
        return super().read(amt)


async def _tolist(aiter):
    results = []
    async for item in aiter:
        results.append(item)
    return results


@pytest.mark.moto
@pytest.mark.asyncio
async def test_streaming_wrapper_validates_content_length():
    body = AsyncBytesIO(b'1234567890')
    stream = response.StreamingBody(body, content_length=10)
    assert await stream.read() == b'1234567890'


@pytest.mark.moto
@pytest.mark.asyncio
async def test_streaming_body_with_invalid_length():
    body = AsyncBytesIO(b'123456789')
    stream = response.StreamingBody(body, content_length=10)
    with pytest.raises(IncompleteReadError):
        assert await stream.read(9) == b'123456789'
        # The next read will have nothing returned and raise
        # an IncompleteReadError because we were expectd 10 bytes, not 9.
        await stream.read()


@pytest.mark.moto
@pytest.mark.asyncio
async def test_streaming_body_with_zero_read():
    body = AsyncBytesIO(b'1234567890')
    stream = response.StreamingBody(body, content_length=10)
    chunk = await stream.read(0)
    assert chunk == b''
    assert await stream.read() == b'1234567890'


@pytest.mark.moto
@pytest.mark.asyncio
async def test_streaming_body_with_single_read():
    body = AsyncBytesIO(b'123456789')
    stream = response.StreamingBody(body, content_length=10)
    with pytest.raises(IncompleteReadError):
        await stream.read()


@pytest.mark.moto
@pytest.mark.asyncio
async def test_streaming_body_closes():
    body = AsyncBytesIO(b'1234567890')
    stream = response.StreamingBody(body, content_length=10)
    assert body.closed is False
    stream.close()
    assert body.closed is True


@pytest.mark.moto
@pytest.mark.asyncio
async def test_default_iter_behavior():
    body = AsyncBytesIO(b'a' * 2048)
    stream = response.StreamingBody(body, content_length=2048)
    chunks = await _tolist(stream)
    assert len(chunks) == 2
    assert chunks, [b'a' * 1024 == b'a' * 1024]


@pytest.mark.moto
@pytest.mark.asyncio
async def test_iter_chunks_single_byte():
    body = AsyncBytesIO(b'abcde')
    stream = response.StreamingBody(body, content_length=5)
    chunks = await _tolist(stream.iter_chunks(chunk_size=1))
    assert chunks, [b'a', b'b', b'c', b'd' == b'e']


@pytest.mark.moto
@pytest.mark.asyncio
async def test_iter_chunks_with_leftover():
    body = AsyncBytesIO(b'abcde')
    stream = response.StreamingBody(body, content_length=5)
    chunks = await _tolist(stream.iter_chunks(chunk_size=2))
    assert chunks, [b'ab', b'cd' == b'e']


@pytest.mark.moto
@pytest.mark.asyncio
async def test_iter_chunks_single_chunk():
    body = AsyncBytesIO(b'abcde')
    stream = response.StreamingBody(body, content_length=5)
    chunks = await _tolist(stream.iter_chunks(chunk_size=1024))
    assert chunks == [b'abcde']


@pytest.mark.moto
@pytest.mark.asyncio
async def test_streaming_line_iterator():
    body = AsyncBytesIO(b'1234567890\n1234567890\n12345')
    stream = response.StreamingBody(body, content_length=27)
    await assert_lines(
        stream.iter_lines(),
        [b'1234567890', b'1234567890', b'12345'],
    )


@pytest.mark.moto
@pytest.mark.asyncio
async def test_streaming_line_iterator_ends_newline():
    body = AsyncBytesIO(b'1234567890\n1234567890\n12345\n')
    stream = response.StreamingBody(body, content_length=28)
    await assert_lines(
        stream.iter_lines(),
        [b'1234567890', b'1234567890', b'12345'],
    )


@pytest.mark.moto
@pytest.mark.asyncio
async def test_streaming_line_iter_chunk_sizes():
    for chunk_size in range(1, 30):
        body = AsyncBytesIO(b'1234567890\n1234567890\n12345')
        stream = response.StreamingBody(body, content_length=27)
        await assert_lines(
            stream.iter_lines(chunk_size),
            [b'1234567890', b'1234567890', b'12345'],
        )


@pytest.mark.moto
@pytest.mark.asyncio
async def test_streaming_body_is_an_iterator():
    body = AsyncBytesIO(b'a' * 1024 + b'b' * 1024 + b'c' * 2)
    stream = response.StreamingBody(body, content_length=2050)
    assert b'a' * 1024 == await stream.__anext__()
    assert b'b' * 1024 == await stream.__anext__()
    assert b'c' * 2 == await stream.__anext__()
    with pytest.raises(StopAsyncIteration):
        await stream.__anext__()


@pytest.mark.moto
@pytest.mark.asyncio
async def test_streaming_line_abstruse_newline_standard():
    for chunk_size in range(1, 30):
        body = AsyncBytesIO(b'1234567890\r\n1234567890\r\n12345\r\n')
        stream = response.StreamingBody(body, content_length=31)
        await assert_lines(
            stream.iter_lines(chunk_size),
            [b'1234567890', b'1234567890', b'12345'],
        )


@pytest.mark.moto
@pytest.mark.asyncio
async def test_streaming_line_empty_body():
    stream = response.StreamingBody(
        AsyncBytesIO(b''),
        content_length=0,
    )
    await assert_lines(stream.iter_lines(), [])
