import aiohttp
import asyncio
import io
import ssl
import aiohttp.http_exceptions
from aiohttp.client import URL
from botocore.endpoint import EndpointCreator, Endpoint, DEFAULT_TIMEOUT, \
    MAX_POOL_CONNECTIONS, logger, history_recorder, create_request_object
from botocore.exceptions import ConnectionClosedError
from botocore.hooks import first_non_none_response
from botocore.utils import is_valid_endpoint_url
from multidict import MultiDict
from urllib.parse import urlparse
from urllib3.response import HTTPHeaderDict
from aiobotocore.response import StreamingBody
from aiobotocore._endpoint_helpers import _text, _IOBaseWrapper, \
    ClientResponseProxy


async def convert_to_response_dict(http_response, operation_model):
    """Convert an HTTP response object to a request dict.

    This converts the requests library's HTTP response object to
    a dictionary.

    :type http_response: botocore.vendored.requests.model.Response
    :param http_response: The HTTP response from an AWS service request.

    :rtype: dict
    :return: A response dictionary which will contain the following keys:
        * headers (dict)
        * status_code (int)
        * body (string or file-like object)

    """
    response_dict = {
        # botocore converts keys to str, so make sure that they are in
        # the expected case. See detailed discussion here:
        # https://github.com/aio-libs/aiobotocore/pull/116
        # aiohttp's CIMultiDict camel cases the headers :(
        'headers': HTTPHeaderDict(
            {k.decode('utf-8').lower(): v.decode('utf-8')
             for k, v in http_response.raw_headers}),
        'status_code': http_response.status_code,
        'context': {
            'operation_name': operation_model.name,
        }
    }
    if response_dict['status_code'] >= 300:
        response_dict['body'] = await http_response.read()
    elif operation_model.has_event_stream_output:
        response_dict['body'] = http_response.raw
    elif operation_model.has_streaming_output:
        length = response_dict['headers'].get('content-length')
        response_dict['body'] = StreamingBody(http_response.raw, length)
    else:
        response_dict['body'] = await http_response.read()
    return response_dict


class AioEndpoint(Endpoint):
    def __init__(self, *args, proxies=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.proxies = proxies or {}

    async def create_request(self, params, operation_model=None):
        request = create_request_object(params)
        if operation_model:
            request.stream_output = any([
                operation_model.has_streaming_output,
                operation_model.has_event_stream_output
            ])
            service_id = operation_model.service_model.service_id.hyphenize()
            event_name = 'request-created.{service_id}.{op_name}'.format(
                service_id=service_id,
                op_name=operation_model.name)
            await self._event_emitter.emit(event_name, request=request,
                                           operation_name=operation_model.name)
        prepared_request = self.prepare_request(request)
        return prepared_request

    async def _send_request(self, request_dict, operation_model):
        attempts = 1
        request = await self.create_request(request_dict, operation_model)
        context = request_dict['context']
        success_response, exception = await self._get_response(
            request, operation_model, context)
        while await self._needs_retry(attempts, operation_model,
                                      request_dict, success_response,
                                      exception):
            attempts += 1
            # If there is a stream associated with the request, we need
            # to reset it before attempting to send the request again.
            # This will ensure that we resend the entire contents of the
            # body.
            request.reset_stream()
            # Create a new request when retried (including a new signature).
            request = await self.create_request(
                request_dict, operation_model)
            success_response, exception = await self._get_response(
                request, operation_model, context)
        if success_response is not None and \
                'ResponseMetadata' in success_response[1]:
            # We want to share num retries, not num attempts.
            total_retries = attempts - 1
            success_response[1]['ResponseMetadata']['RetryAttempts'] = \
                total_retries
        if exception is not None:
            raise exception
        else:
            return success_response

    async def _get_response(self, request, operation_model, context):
        # This will return a tuple of (success_response, exception)
        # and success_response is itself a tuple of
        # (http_response, parsed_dict).
        # If an exception occurs then the success_response is None.
        # If no exception occurs then exception is None.
        success_response, exception = await self._do_get_response(
            request, operation_model)
        kwargs_to_emit = {
            'response_dict': None,
            'parsed_response': None,
            'context': context,
            'exception': exception,
        }
        if success_response is not None:
            http_response, parsed_response = success_response
            kwargs_to_emit['parsed_response'] = parsed_response
            kwargs_to_emit['response_dict'] = await convert_to_response_dict(
                http_response, operation_model)
        service_id = operation_model.service_model.service_id.hyphenize()
        await self._event_emitter.emit(
            'response-received.%s.%s' % (
                service_id, operation_model.name), **kwargs_to_emit)
        return success_response, exception

    async def _do_get_response(self, request, operation_model):
        try:
            logger.debug("Sending http request: %s", request)
            history_recorder.record('HTTP_REQUEST', {
                'method': request.method,
                'headers': request.headers,
                'streaming': operation_model.has_streaming_input,
                'url': request.url,
                'body': request.body
            })
            service_id = operation_model.service_model.service_id.hyphenize()
            event_name = 'before-send.%s.%s' % (
                service_id, operation_model.name)
            responses = await self._event_emitter.emit(event_name,
                                                       request=request)
            http_response = first_non_none_response(responses)
            if http_response is None:
                http_response = await self._send(request)
        except aiohttp.ClientConnectionError as e:
            e.request = request  # botocore expects the request property
            return None, e
        except aiohttp.http_exceptions.BadStatusLine:
            better_exception = ConnectionClosedError(
                endpoint_url=request.url, request=request)
            return None, better_exception
        except Exception as e:
            logger.debug("Exception received when sending HTTP request.",
                         exc_info=True)
            return None, e

        # This returns the http_response and the parsed_data.
        response_dict = await convert_to_response_dict(http_response,
                                                       operation_model)

        http_response_record_dict = response_dict.copy()
        http_response_record_dict['streaming'] = \
            operation_model.has_streaming_output
        history_recorder.record('HTTP_RESPONSE', http_response_record_dict)

        protocol = operation_model.metadata['protocol']
        parser = self._response_parser_factory.create_parser(protocol)
        parsed_response = parser.parse(
            response_dict, operation_model.output_shape)
        if http_response.status_code >= 300:
            self._add_modeled_error_fields(
                response_dict, parsed_response,
                operation_model, parser,
            )
        history_recorder.record('PARSED_RESPONSE', parsed_response)
        return (http_response, parsed_response), None

    # NOTE: The only line changed here changing time.sleep to asyncio.sleep
    async def _needs_retry(self, attempts, operation_model, request_dict,
                           response=None, caught_exception=None):
        service_id = operation_model.service_model.service_id.hyphenize()
        event_name = 'needs-retry.%s.%s' % (
            service_id,
            operation_model.name)
        responses = await self._event_emitter.emit(
            event_name, response=response, endpoint=self,
            operation=operation_model, attempts=attempts,
            caught_exception=caught_exception, request_dict=request_dict)
        handler_response = first_non_none_response(responses)
        if handler_response is None:
            return False
        else:
            # Request needs to be retried, and we need to sleep
            # for the specified number of times.
            logger.debug("Response received to retry, sleeping for "
                         "%s seconds", handler_response)
            await asyncio.sleep(handler_response)
            return True

    async def _send(self, request):
        # Note: When using aiobotocore with dynamodb, requests fail on crc32
        # checksum computation as soon as the response data reaches ~5KB.
        # When AWS response is gzip compressed:
        # 1. aiohttp is automatically decompressing the data
        # (http://aiohttp.readthedocs.io/en/stable/client.html#binary-response-content)
        # 2. botocore computes crc32 on the uncompressed data bytes and fails
        # cause crc32 has been computed on the compressed data
        # The following line forces aws not to use gzip compression,
        # if there is a way to configure aiohttp not to perform decompression,
        # we can remove the following line and take advantage of
        # aws gzip compression.
        # https://github.com/boto/botocore/issues/1255
        url = request.url
        headers = request.headers
        data = request.body

        headers['Accept-Encoding'] = 'identity'
        headers_ = MultiDict(
            (z[0], _text(z[1], encoding='utf-8')) for z in headers.items())

        # botocore does this during the request so we do this here as well
        # TODO: this should be part of the ClientSession, perhaps make wrapper
        proxy = self.proxies.get(urlparse(url.lower()).scheme)
        
        if proxy:
            proxy = self._fix_proxy_url(proxy)

        if isinstance(data, io.IOBase):
            data = _IOBaseWrapper(data)

        url = URL(url, encoded=True)
        resp = await self.http_session.request(
            request.method, url=url, headers=headers_, data=data, proxy=proxy)

        # If we're not streaming, read the content so we can retry any timeout
        #  errors, see:
        # https://github.com/boto/botocore/blob/develop/botocore/vendored/requests/sessions.py#L604
        if not request.stream_output:
            await resp.read()

        return resp

    def _fix_proxy_url(self, proxy_url):
        if proxy_url.startswith('http:') or proxy_url.startswith('https:'):
            return proxy_url
        elif proxy_url.startswith('//'):
            return 'http:' + proxy_url
        else:
            return 'http://' + proxy_url

class AioEndpointCreator(EndpointCreator):
    # TODO: handle socket_options
    def create_endpoint(self, service_model, region_name, endpoint_url,
                        verify=None, response_parser_factory=None,
                        timeout=DEFAULT_TIMEOUT,
                        max_pool_connections=MAX_POOL_CONNECTIONS,
                        http_session_cls=aiohttp.ClientSession,
                        proxies=None,
                        socket_options=None,
                        client_cert=None,
                        connector_args=None):
        if not is_valid_endpoint_url(endpoint_url):

            raise ValueError("Invalid endpoint: %s" % endpoint_url)
        if proxies is None:
            proxies = self._get_proxies(endpoint_url)
        endpoint_prefix = service_model.endpoint_prefix

        logger.debug('Setting %s timeout as %s', endpoint_prefix, timeout)

        if isinstance(timeout, (list, tuple)):
            conn_timeout, read_timeout = timeout
        else:
            conn_timeout = read_timeout = timeout

        if connector_args is None:
            # AWS has a 20 second idle timeout:
            #   https://forums.aws.amazon.com/message.jspa?messageID=215367
            # aiohttp default timeout is 30s so set something reasonable here
            connector_args = dict(keepalive_timeout=12)

        timeout = aiohttp.ClientTimeout(
            sock_connect=conn_timeout,
            sock_read=read_timeout
        )

        ssl_context = None
        if client_cert:
            if isinstance(client_cert, str):
                key_file = None
                cert_file = client_cert
            elif isinstance(client_cert, tuple):
                cert_file, key_file = client_cert
            else:
                assert False

            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(cert_file, key_file)

        connector = aiohttp.TCPConnector(
            limit=max_pool_connections,
            verify_ssl=self._get_verify_value(verify),
            ssl_context=ssl_context,
            **connector_args)

        aio_session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            skip_auto_headers={'CONTENT-TYPE'},
            response_class=ClientResponseProxy,
            auto_decompress=False)

        return AioEndpoint(
            endpoint_url,
            endpoint_prefix=endpoint_prefix,
            event_emitter=self._event_emitter,
            response_parser_factory=response_parser_factory,
            http_session=aio_session,
            proxies=proxies)
