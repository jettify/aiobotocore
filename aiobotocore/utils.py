import asyncio
import logging
import json
from contextlib import asynccontextmanager
import inspect

import aiohttp.client_exceptions
from botocore.utils import ContainerMetadataFetcher, InstanceMetadataFetcher, \
    IMDSFetcher, get_environ_proxies, BadIMDSRequestError, S3RegionRedirector, \
    ClientError, InstanceMetadataRegionFetcher, IMDSRegionProvider, \
    resolve_imds_endpoint_mode, ReadTimeoutError, HTTPClientError, LocationParseError
from botocore.exceptions import (
    InvalidIMDSEndpointError, MetadataRetrievalError,
)
import botocore.awsrequest
import aiobotocore.httpsession


logger = logging.getLogger(__name__)
RETRYABLE_HTTP_ERRORS = (aiohttp.client_exceptions.ClientError, asyncio.TimeoutError)


class _RefCountedSession(aiobotocore.httpsession.AIOHTTPSession):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__ref_count = 0
        self.__lock = None

    @asynccontextmanager
    async def acquire(self):
        if not self.__lock:
            self.__lock = asyncio.Lock()

        # ensure we have a session
        async with self.__lock:
            self.__ref_count += 1

            try:
                if self.__ref_count == 1:
                    await self.__aenter__()
            except BaseException:
                self.__ref_count -= 1
                raise

        try:
            yield self
        finally:
            async with self.__lock:
                if self.__ref_count == 1:
                    await self.__aexit__(None, None, None)

                self.__ref_count -= 1


class AioIMDSFetcher(IMDSFetcher):
    def __init__(self, *args, session=None, **kwargs):
        super(AioIMDSFetcher, self).__init__(*args, **kwargs)
        self._session = session or _RefCountedSession(
            timeout=self._timeout,
            proxies=get_environ_proxies(self._base_url),
        )

    async def _fetch_metadata_token(self):
        self._assert_enabled()
        url = self._construct_url(self._TOKEN_PATH)
        headers = {
            'x-aws-ec2-metadata-token-ttl-seconds': self._TOKEN_TTL,
        }
        self._add_user_agent(headers)

        request = botocore.awsrequest.AWSRequest(
            method='PUT', url=url, headers=headers)

        async with self._session.acquire() as session:
            for i in range(self._num_attempts):
                try:
                    response = await session.send(request.prepare())
                    if response.status_code == 200:
                        return await response.text
                    elif response.status_code in (404, 403, 405):
                        return None
                    elif response.status_code in (400,):
                        raise BadIMDSRequestError(request)
                except ReadTimeoutError:
                    return None
                except RETRYABLE_HTTP_ERRORS as e:
                    logger.debug(
                        "Caught retryable HTTP exception while making metadata "
                        "service request to %s: %s", url, e, exc_info=True)
                except HTTPClientError as e:
                    if isinstance(e.kwargs.get('error'), LocationParseError):
                        raise InvalidIMDSEndpointError(endpoint=url, error=e)
                    else:
                        raise

        return None

    async def _get_request(self, url_path, retry_func, token=None):
        self._assert_enabled()
        if retry_func is None:
            retry_func = self._default_retry
        url = self._construct_url(url_path)
        headers = {}
        if token is not None:
            headers['x-aws-ec2-metadata-token'] = token
        self._add_user_agent(headers)

        async with self._session.acquire() as session:
            for i in range(self._num_attempts):
                try:
                    request = botocore.awsrequest.AWSRequest(
                        method='GET', url=url, headers=headers)
                    response = await session.send(request.prepare())
                    should_retry = retry_func(response)
                    if inspect.isawaitable(should_retry):
                        should_retry = await should_retry

                    if not should_retry:
                        return response
                except RETRYABLE_HTTP_ERRORS as e:
                    logger.debug(
                        "Caught retryable HTTP exception while making metadata "
                        "service request to %s: %s", url, e, exc_info=True)
        raise self._RETRIES_EXCEEDED_ERROR_CLS()

    async def _default_retry(self, response):
        return (
                await self._is_non_ok_response(response) or
                await self._is_empty(response)
        )

    async def _is_non_ok_response(self, response):
        if response.status_code != 200:
            await self._log_imds_response(response, 'non-200', log_body=True)
            return True
        return False

    async def _is_empty(self, response):
        if not await response.content:
            await self._log_imds_response(response, 'no body', log_body=True)
            return True
        return False

    async def _log_imds_response(self, response, reason_to_log, log_body=False):
        statement = (
            "Metadata service returned %s response "
            "with status code of %s for url: %s"
        )
        logger_args = [
            reason_to_log, response.status_code, response.url
        ]
        if log_body:
            statement += ", content body: %s"
            logger_args.append(await response.content)
        logger.debug(statement, *logger_args)


class AioInstanceMetadataFetcher(AioIMDSFetcher, InstanceMetadataFetcher):
    async def retrieve_iam_role_credentials(self):
        try:
            token = await self._fetch_metadata_token()
            role_name = await self._get_iam_role(token)
            credentials = await self._get_credentials(role_name, token)
            if self._contains_all_credential_fields(credentials):
                return {
                    'role_name': role_name,
                    'access_key': credentials['AccessKeyId'],
                    'secret_key': credentials['SecretAccessKey'],
                    'token': credentials['Token'],
                    'expiry_time': credentials['Expiration'],
                }
            else:
                if 'Code' in credentials and 'Message' in credentials:
                    logger.debug('Error response received when retrieving'
                                 'credentials: %s.', credentials)
                return {}
        except self._RETRIES_EXCEEDED_ERROR_CLS:
            logger.debug("Max number of attempts exceeded (%s) when "
                         "attempting to retrieve data from metadata service.",
                         self._num_attempts)
        except BadIMDSRequestError as e:
            logger.debug("Bad IMDS request: %s", e.request)
        return {}

    async def _get_iam_role(self, token=None):
        return await (await self._get_request(
            url_path=self._URL_PATH,
            retry_func=self._needs_retry_for_role_name,
            token=token,
        )).text

    async def _get_credentials(self, role_name, token=None):
        r = await self._get_request(
            url_path=self._URL_PATH + role_name,
            retry_func=self._needs_retry_for_credentials,
            token=token
        )
        return json.loads(await r.text)

    async def _is_invalid_json(self, response):
        try:
            json.loads(await response.text)
            return False
        except ValueError:
            await self._log_imds_response(response, 'invalid json')
            return True

    async def _needs_retry_for_role_name(self, response):
        return (
                await self._is_non_ok_response(response) or
                await self._is_empty(response)
        )

    async def _needs_retry_for_credentials(self, response):
        return (
                await self._is_non_ok_response(response) or
                await self._is_empty(response) or
                await self._is_invalid_json(response)
        )

class AioIMDSRegionProvider(IMDSRegionProvider):
    async def provide(self):
        """Provide the region value from IMDS."""
        instance_region = await self._get_instance_metadata_region()
        return instance_region

    async def _get_instance_metadata_region(self):
        fetcher = self._get_fetcher()
        region = await fetcher.retrieve_region()
        return region

    def _create_fetcher(self):
        metadata_timeout = self._session.get_config_variable(
            'metadata_service_timeout')
        metadata_num_attempts = self._session.get_config_variable(
            'metadata_service_num_attempts')
        imds_config = {
            'ec2_metadata_service_endpoint': self._session.get_config_variable(
                'ec2_metadata_service_endpoint'),
            'ec2_metadata_service_endpoint_mode': resolve_imds_endpoint_mode(
                self._session
            )
        }
        fetcher = AioInstanceMetadataRegionFetcher(
            timeout=metadata_timeout,
            num_attempts=metadata_num_attempts,
            env=self._environ,
            user_agent=self._session.user_agent(),
            config=imds_config,
        )
        return fetcher


class AioInstanceMetadataRegionFetcher(AioIMDSFetcher, InstanceMetadataRegionFetcher):
    async def retrieve_region(self):
        try:
            region = await self._get_region()
            return region
        except self._RETRIES_EXCEEDED_ERROR_CLS:
            logger.debug("Max number of attempts exceeded (%s) when "
                         "attempting to retrieve data from metadata service.",
                         self._num_attempts)
        return None

    async def _get_region(self):
        token = await self._fetch_metadata_token()
        response = await self._get_request(
            url_path=self._URL_PATH,
            retry_func=self._default_retry,
            token=token
        )
        availability_zone = await response.text
        region = availability_zone[:-1]
        return region


class AioS3RegionRedirector(S3RegionRedirector):
    async def redirect_from_error(self, request_dict, response, operation, **kwargs):
        if response is None:
            # This could be none if there was a ConnectionError or other
            # transport error.
            return

        if self._is_s3_accesspoint(request_dict.get('context', {})):
            logger.debug(
                'S3 request was previously to an accesspoint, not redirecting.'
            )
            return

        if request_dict.get('context', {}).get('s3_redirected'):
            logger.debug(
                'S3 request was previously redirected, not redirecting.')
            return

        error = response[1].get('Error', {})
        error_code = error.get('Code')
        response_metadata = response[1].get('ResponseMetadata', {})

        # We have to account for 400 responses because
        # if we sign a Head* request with the wrong region,
        # we'll get a 400 Bad Request but we won't get a
        # body saying it's an "AuthorizationHeaderMalformed".
        is_special_head_object = (
            error_code in ['301', '400'] and
            operation.name == 'HeadObject'
        )
        is_special_head_bucket = (
            error_code in ['301', '400'] and
            operation.name == 'HeadBucket' and
            'x-amz-bucket-region' in response_metadata.get('HTTPHeaders', {})
        )
        is_wrong_signing_region = (
            error_code == 'AuthorizationHeaderMalformed' and
            'Region' in error
        )
        is_redirect_status = response[0] is not None and \
            response[0].status_code in [301, 302, 307]
        is_permanent_redirect = error_code == 'PermanentRedirect'
        if not any([is_special_head_object, is_wrong_signing_region,
                    is_permanent_redirect, is_special_head_bucket,
                    is_redirect_status]):
            return

        bucket = request_dict['context']['signing']['bucket']
        client_region = request_dict['context'].get('client_region')
        new_region = await self.get_bucket_region(bucket, response)

        if new_region is None:
            logger.debug(
                "S3 client configured for region %s but the bucket %s is not "
                "in that region and the proper region could not be "
                "automatically determined." % (client_region, bucket))
            return

        logger.debug(
            "S3 client configured for region %s but the bucket %s is in region"
            " %s; Please configure the proper region to avoid multiple "
            "unnecessary redirects and signing attempts." % (
                client_region, bucket, new_region))
        endpoint = self._endpoint_resolver.resolve('s3', new_region)
        endpoint = endpoint['endpoint_url']

        signing_context = {
            'region': new_region,
            'bucket': bucket,
            'endpoint': endpoint
        }
        request_dict['context']['signing'] = signing_context

        self._cache[bucket] = signing_context
        self.set_request_url(request_dict, request_dict['context'])

        request_dict['context']['s3_redirected'] = True

        # Return 0 so it doesn't wait to retry
        return 0

    async def get_bucket_region(self, bucket, response):
        # First try to source the region from the headers.
        service_response = response[1]
        response_headers = service_response['ResponseMetadata']['HTTPHeaders']
        if 'x-amz-bucket-region' in response_headers:
            return response_headers['x-amz-bucket-region']

        # Next, check the error body
        region = service_response.get('Error', {}).get('Region', None)
        if region is not None:
            return region

        # Finally, HEAD the bucket. No other choice sadly.
        try:
            response = await self._client.head_bucket(Bucket=bucket)
            headers = response['ResponseMetadata']['HTTPHeaders']
        except ClientError as e:
            headers = e.response['ResponseMetadata']['HTTPHeaders']

        region = headers.get('x-amz-bucket-region', None)
        return region


class AioContainerMetadataFetcher(ContainerMetadataFetcher):
    def __init__(self, session=None, sleep=asyncio.sleep):
        if session is None:
            session = _RefCountedSession(
                timeout=self.TIMEOUT_SECONDS
            )
        self._session = session
        self._sleep = sleep

    async def retrieve_full_uri(self, full_url, headers=None):
        self._validate_allowed_url(full_url)
        return await self._retrieve_credentials(full_url, headers)

    async def retrieve_uri(self, relative_uri):
        """Retrieve JSON metadata from ECS metadata.

        :type relative_uri: str
        :param relative_uri: A relative URI, e.g "/foo/bar?id=123"

        :return: The parsed JSON response.

        """
        full_url = self.full_url(relative_uri)
        return await self._retrieve_credentials(full_url)

    async def _retrieve_credentials(self, full_url, extra_headers=None):
        headers = {'Accept': 'application/json'}
        if extra_headers is not None:
            headers.update(extra_headers)
        attempts = 0
        while True:
            try:
                return await self._get_response(
                    full_url, headers, self.TIMEOUT_SECONDS)
            except MetadataRetrievalError as e:
                logger.debug("Received error when attempting to retrieve "
                             "container metadata: %s", e, exc_info=True)
                await self._sleep(self.SLEEP_TIME)
                attempts += 1
                if attempts >= self.RETRY_ATTEMPTS:
                    raise

    async def _get_response(self, full_url, headers, timeout):
        try:
            async with self._session.acquire() as session:
                AWSRequest = botocore.awsrequest.AWSRequest
                request = AWSRequest(method='GET', url=full_url, headers=headers)
                response = await session.send(request.prepare())
                response_text = (await response.content).decode('utf-8')

                if response.status_code != 200:
                    raise MetadataRetrievalError(
                        error_msg=(
                                      "Received non 200 response (%s) from ECS metadata: %s"
                                  ) % (response.status_code, response_text))
                try:
                    return json.loads(response_text)
                except ValueError:
                    error_msg = (
                        "Unable to parse JSON returned from ECS metadata services"
                    )
                    logger.debug('%s:%s', error_msg, response_text)
                    raise MetadataRetrievalError(error_msg=error_msg)

        except RETRYABLE_HTTP_ERRORS as e:
            error_msg = ("Received error when attempting to retrieve "
                         "ECS metadata: %s" % e)
        raise MetadataRetrievalError(error_msg=error_msg)
