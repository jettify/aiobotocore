# import asyncio

# import aiohttp.http_exceptions
import botocore.retryhandler
import wrapt

# Monkey patching: We need to insert the aiohttp exception equivalents
# The only other way to do this would be to have another config file :(
# _aiohttp_retryable_exceptions = [
#    aiohttp.ClientConnectionError,
#    aiohttp.ClientPayloadError,
#    aiohttp.ServerDisconnectedError,
#    aiohttp.http_exceptions.HttpProcessingError,
#    asyncio.TimeoutError,
# ]
#
# botocore.retryhandler.EXCEPTION_MAP['GENERAL_CONNECTION_ERROR'].extend(
#    _aiohttp_retryable_exceptions
# )


def _text(s, encoding='utf-8', errors='strict'):
    if isinstance(s, bytes):
        return s.decode(encoding, errors)
    return s  # pragma: no cover


# Unfortunately aiohttp changed the behavior of streams:
#   github.com/aio-libs/aiohttp/issues/1907
# We need this wrapper until we have a final resolution
class _IOBaseWrapper(wrapt.ObjectProxy):
    def close(self):
        # this stream should not be closed by aiohttp, like 1.x
        pass
