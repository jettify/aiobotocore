import asyncio

from botocore.endpoint import (
    DEFAULT_TIMEOUT,
    MAX_POOL_CONNECTIONS,
    Endpoint,
    EndpointCreator,
    HTTPClientError,
    create_request_object,
    history_recorder,
    is_valid_endpoint_url,
    is_valid_ipv6_endpoint_url,
    logger,
)
from botocore.hooks import first_non_none_response
from urllib3.response import HTTPHeaderDict

from aiobotocore.httpchecksum import handle_checksum_body
from aiobotocore.httpsession import AIOHTTPSession
from aiobotocore.response import StreamingBody

from ._helpers import resolve_awaitable


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
            {
                k.decode('utf-8').lower(): v.decode('utf-8')
                for k, v in http_response.raw.raw_headers
            }
        ),
        'status_code': http_response.status_code,
        'context': {
            'operation_name': operation_model.name,
        },
    }
    if response_dict['status_code'] >= 300:
        response_dict['body'] = await resolve_awaitable(http_response.content)
    elif operation_model.has_event_stream_output:
        response_dict['body'] = http_response.raw
    elif operation_model.has_streaming_output:
        length = response_dict['headers'].get('content-length')
        response_dict['body'] = StreamingBody(http_response.raw, length)
    else:
        response_dict['body'] = await resolve_awaitable(http_response.content)
    return response_dict


class AioEndpoint(Endpoint):
    async def close(self):
        await self.http_session.close()

    async def create_request(self, params, operation_model=None):
        request = create_request_object(params)
        if operation_model:
            request.stream_output = any(
                [
                    operation_model.has_streaming_output,
                    operation_model.has_event_stream_output,
                ]
            )
            service_id = operation_model.service_model.service_id.hyphenize()
            event_name = 'request-created.{service_id}.{op_name}'.format(
                service_id=service_id, op_name=operation_model.name
            )
            await self._event_emitter.emit(
                event_name,
                request=request,
                operation_name=operation_model.name,
            )
        prepared_request = self.prepare_request(request)
        return prepared_request

    async def _send_request(self, request_dict, operation_model):
        attempts = 1
        context = request_dict['context']
        self._update_retries_context(context, attempts)
        request = await self.create_request(request_dict, operation_model)
        success_response, exception = await self._get_response(
            request, operation_model, context
        )
        while await self._needs_retry(
            attempts,
            operation_model,
            request_dict,
            success_response,
            exception,
        ):
            attempts += 1
            self._update_retries_context(context, attempts, success_response)
            # If there is a stream associated with the request, we need
            # to reset it before attempting to send the request again.
            # This will ensure that we resend the entire contents of the
            # body.
            request.reset_stream()
            # Create a new request when retried (including a new signature).
            request = await self.create_request(request_dict, operation_model)
            success_response, exception = await self._get_response(
                request, operation_model, context
            )
        if (
            success_response is not None
            and 'ResponseMetadata' in success_response[1]
        ):
            # We want to share num retries, not num attempts.
            total_retries = attempts - 1
            success_response[1]['ResponseMetadata'][
                'RetryAttempts'
            ] = total_retries
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
            request, operation_model, context
        )
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
                http_response, operation_model
            )
        service_id = operation_model.service_model.service_id.hyphenize()
        await self._event_emitter.emit(
            f"response-received.{service_id}.{operation_model.name}",
            **kwargs_to_emit,
        )
        return success_response, exception

    async def _do_get_response(self, request, operation_model, context):
        try:
            logger.debug("Sending http request: %s", request)
            history_recorder.record(
                'HTTP_REQUEST',
                {
                    'method': request.method,
                    'headers': request.headers,
                    'streaming': operation_model.has_streaming_input,
                    'url': request.url,
                    'body': request.body,
                },
            )
            service_id = operation_model.service_model.service_id.hyphenize()
            event_name = f"before-send.{service_id}.{operation_model.name}"
            responses = await self._event_emitter.emit(
                event_name, request=request
            )
            http_response = first_non_none_response(responses)
            if http_response is None:
                http_response = await self._send(request)
        except HTTPClientError as e:
            return (None, e)
        except Exception as e:
            logger.debug(
                "Exception received when sending HTTP request.", exc_info=True
            )
            return (None, e)

        # This returns the http_response and the parsed_data.
        response_dict = await convert_to_response_dict(
            http_response, operation_model
        )
        await handle_checksum_body(
            http_response,
            response_dict,
            context,
            operation_model,
        )

        http_response_record_dict = response_dict.copy()
        http_response_record_dict[
            'streaming'
        ] = operation_model.has_streaming_output
        history_recorder.record('HTTP_RESPONSE', http_response_record_dict)

        protocol = operation_model.metadata['protocol']
        parser = self._response_parser_factory.create_parser(protocol)

        if asyncio.iscoroutinefunction(parser.parse):
            parsed_response = await parser.parse(
                response_dict, operation_model.output_shape
            )
        else:
            parsed_response = parser.parse(
                response_dict, operation_model.output_shape
            )

        if http_response.status_code >= 300:
            await self._add_modeled_error_fields(
                response_dict,
                parsed_response,
                operation_model,
                parser,
            )
        history_recorder.record('PARSED_RESPONSE', parsed_response)
        return (http_response, parsed_response), None

    async def _add_modeled_error_fields(
        self,
        response_dict,
        parsed_response,
        operation_model,
        parser,
    ):
        error_code = parsed_response.get("Error", {}).get("Code")
        if error_code is None:
            return
        service_model = operation_model.service_model
        error_shape = service_model.shape_for_error_code(error_code)
        if error_shape is None:
            return

        if asyncio.iscoroutinefunction(parser.parse):
            modeled_parse = await parser.parse(response_dict, error_shape)
        else:
            modeled_parse = parser.parse(response_dict, error_shape)
        # TODO: avoid naming conflicts with ResponseMetadata and Error
        parsed_response.update(modeled_parse)

    # NOTE: The only line changed here changing time.sleep to asyncio.sleep
    async def _needs_retry(
        self,
        attempts,
        operation_model,
        request_dict,
        response=None,
        caught_exception=None,
    ):
        service_id = operation_model.service_model.service_id.hyphenize()
        event_name = f"needs-retry.{service_id}.{operation_model.name}"
        responses = await self._event_emitter.emit(
            event_name,
            response=response,
            endpoint=self,
            operation=operation_model,
            attempts=attempts,
            caught_exception=caught_exception,
            request_dict=request_dict,
        )
        handler_response = first_non_none_response(responses)
        if handler_response is None:
            return False
        else:
            # Request needs to be retried, and we need to sleep
            # for the specified number of times.
            logger.debug(
                "Response received to retry, sleeping for %s seconds",
                handler_response,
            )
            await asyncio.sleep(handler_response)
            return True

    async def _send(self, request):
        return await self.http_session.send(request)


class AioEndpointCreator(EndpointCreator):
    def create_endpoint(
        self,
        service_model,
        region_name,
        endpoint_url,
        verify=None,
        response_parser_factory=None,
        timeout=DEFAULT_TIMEOUT,
        max_pool_connections=MAX_POOL_CONNECTIONS,
        http_session_cls=AIOHTTPSession,
        proxies=None,
        socket_options=None,
        client_cert=None,
        proxies_config=None,
        connector_args=None,
    ):
        if not is_valid_endpoint_url(
            endpoint_url
        ) and not is_valid_ipv6_endpoint_url(endpoint_url):
            raise ValueError("Invalid endpoint: %s" % endpoint_url)

        if proxies is None:
            proxies = self._get_proxies(endpoint_url)
        endpoint_prefix = service_model.endpoint_prefix

        logger.debug('Setting %s timeout as %s', endpoint_prefix, timeout)
        http_session = http_session_cls(
            timeout=timeout,
            proxies=proxies,
            verify=self._get_verify_value(verify),
            max_pool_connections=max_pool_connections,
            socket_options=socket_options,
            client_cert=client_cert,
            proxies_config=proxies_config,
            connector_args=connector_args,
        )

        return AioEndpoint(
            endpoint_url,
            endpoint_prefix=endpoint_prefix,
            event_emitter=self._event_emitter,
            response_parser_factory=response_parser_factory,
            http_session=http_session,
        )
