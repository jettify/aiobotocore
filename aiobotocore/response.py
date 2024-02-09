import asyncio

import aiohttp.client_exceptions
import httpx
import wrapt
from botocore.response import (
    IncompleteReadError,
    ReadTimeoutError,
    ResponseStreamingError,
)

from aiobotocore import parsers


class AioReadTimeoutError(ReadTimeoutError, asyncio.TimeoutError):
    pass


class StreamingBody(wrapt.ObjectProxy):
    """Wrapper class for an http response body.

    This provides a few additional conveniences that do not exist
    in the urllib3 model:

        * Auto validation of content length, if the amount of bytes
          we read does not match the content length, an exception
          is raised.
    """

    _DEFAULT_CHUNK_SIZE = 1024

    # TODO [httpx]: this type is not fully correct .. I think
    def __init__(self, raw_stream: httpx.Response, content_length: str):
        print(next(raw_stream.aiter_bytes()))
        print(next(raw_stream.aiter_raw()))
        breakpoint()
        super().__init__(raw_stream)
        self._self_content_length = content_length
        self._self_amount_read = 0

    # https://github.com/GrahamDumpleton/wrapt/issues/73
    # TODO [httpx]: httpx doesn't seem to do context manager for the response
    # so I kinda hate these
    async def __aenter__(self):
        if isinstance(self.__wrapped__, httpx.Response):
            return self
            # return await self.__wrapped__.aiter_bytes()
        else:
            # not encountered in test suite, but maybe still needs to be supported?
            assert False
            return await self.__wrapped__.__aenter__()

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if isinstance(self.__wrapped__, httpx.Response):
            await self.__wrapped__.aclose()
        else:
            # not encountered in test suite, but maybe still needs to be supported?
            assert False
            return await self.__wrapped__.__aexit__(exc_type, exc_val, exc_tb)

    # NOTE: set_socket_timeout was only for when requests didn't support
    #       read timeouts, so not needed
    def readable(self):
        return not self.at_eof()

    async def read(self, amt=None):
        """Read at most amt bytes from the stream.

        If the amt argument is omitted, read all data.
        """
        # botocore to aiohttp mapping
        try:
            import httpx

            if isinstance(self.__wrapped__, httpx.Response):
                if amt is None:
                    chunk = self.__wrapped__.content
                else:
                    # TODO [httpx]: to read a specific number of bytes I think we need to
                    # stream into a bytearray, or something
                    # ... actually no I'm completely flummoxed by this. I get
                    # StreamConsumed errors, and apparently the text is available in
                    # self.__wrapped__.text npnp. Possible we need to do
                    # "For situations when context block usage is not practical, it is
                    # possible to enter "manual mode" by sending a Request instance
                    # using client.send(..., stream=True)."

                    # use memoryview?
                    #bb = bytearray()
                    kk = self.__wrapped__.aiter_raw(amt)
                    chunk = await anext(kk)
                    #for i in range(amt):
                    #    breakpoint()
                    #    print(await anext(kk))
                    #    bb.append(await anext(kk))
                    # TODO [httpx]: this does not seem to get triggered .... idk
            else:
                chunk = await self.__wrapped__.content.read(
                    amt if amt is not None else -1
                )
        except asyncio.TimeoutError as e:
            raise AioReadTimeoutError(
                endpoint_url=self.__wrapped__.url, error=e
            )
        # TODO [httpx]
        except aiohttp.client_exceptions.ClientConnectionError as e:
            raise ResponseStreamingError(error=e)

        self._self_amount_read += len(chunk)
        if amt is None or (not chunk and amt > 0):
            # If the server sends empty contents or
            # we ask to read all of the contents, then we know
            # we need to verify the content length.
            self._verify_content_length()
        return chunk

    async def readlines(self):
        # assuming this is not an iterator
        lines = [line async for line in self.iter_lines()]
        return lines

    def __aiter__(self):
        """Return an iterator to yield 1k chunks from the raw stream."""
        return self.iter_chunks(self._DEFAULT_CHUNK_SIZE)

    async def __anext__(self):
        """Return the next 1k chunk from the raw stream."""
        current_chunk = await self.read(self._DEFAULT_CHUNK_SIZE)
        if current_chunk:
            return current_chunk
        raise StopAsyncIteration

    anext = __anext__

    async def iter_lines(self, chunk_size=_DEFAULT_CHUNK_SIZE, keepends=False):
        """Return an iterator to yield lines from the raw stream.

        This is achieved by reading chunk of bytes (of size chunk_size) at a
        time from the raw stream, and then yielding lines from there.
        """
        pending = b''
        async for chunk in self.iter_chunks(chunk_size):
            lines = (pending + chunk).splitlines(True)
            for line in lines[:-1]:
                yield line.splitlines(keepends)[0]
            pending = lines[-1]
        if pending:
            yield pending.splitlines(keepends)[0]

    async def iter_chunks(self, chunk_size=_DEFAULT_CHUNK_SIZE):
        """Return an iterator to yield chunks of chunk_size bytes from the raw
        stream.
        """
        while True:
            current_chunk = await self.read(chunk_size)
            if current_chunk == b"":
                break
            yield current_chunk

    def _verify_content_length(self):
        # See: https://github.com/kennethreitz/requests/issues/1855
        # Basically, our http library doesn't do this for us, so we have
        # to do this our self.
        if (
            self._self_content_length is not None
            and self._self_amount_read != int(self._self_content_length)
        ):
            raise IncompleteReadError(
                actual_bytes=self._self_amount_read,
                expected_bytes=int(self._self_content_length),
            )

    def tell(self):
        return self._self_amount_read


async def get_response(operation_model, http_response):
    protocol = operation_model.metadata['protocol']
    response_dict = {
        'headers': http_response.headers,
        'status_code': http_response.status_code,
    }
    # TODO: Unfortunately, we have to have error logic here.
    # If it looks like an error, in the streaming response case we
    # need to actually grab the contents.
    if response_dict['status_code'] >= 300:
        response_dict['body'] = await http_response.content
    elif operation_model.has_streaming_output:
        response_dict['body'] = StreamingBody(
            http_response.raw, response_dict['headers'].get('content-length')
        )
    else:
        response_dict['body'] = await http_response.content

    parser = parsers.create_parser(protocol)
    if asyncio.iscoroutinefunction(parser.parse):
        parsed = await parser.parse(
            response_dict, operation_model.output_shape
        )
    else:
        parsed = parser.parse(response_dict, operation_model.output_shape)
    return http_response, parsed
