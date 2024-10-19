Changes
-------

2.15.2 (2024-10-09)
^^^^^^^^^^^^^^^^^^^
* relax botocore dependency specification

2.15.1 (2024-09-19)
^^^^^^^^^^^^^^^^^^^
* relax botocore dependency specification

2.15.0 (2024-09-10)
^^^^^^^^^^^^^^^^^^^
* bump botocore dependency specification

2.14.0 (2024-08-28)
^^^^^^^^^^^^^^^^^^^
* bump botocore dependency specification

2.13.3 (2024-08-22)
^^^^^^^^^^^^^^^^^^^
* fix ``create_waiter_with_client()``
* relax botocore dependency specification

2.13.2 (2024-07-18)
^^^^^^^^^^^^^^^^^^^
* fix for #1125 due to missing patch of StreamingChecksumBody

2.13.1 (2024-06-24)
^^^^^^^^^^^^^^^^^^^
* bump botocore dependency specification

2.13.0 (2024-05-16)
^^^^^^^^^^^^^^^^^^^
* address breaking change introduced in `aiohttp==3.9.2` #882

2.12.4 (2024-05-16)
^^^^^^^^^^^^^^^^^^^
* bump botocore dependency specification

2.12.3 (2024-04-11)
^^^^^^^^^^^^^^^^^^^
* relax botocore dependency specification

2.12.2 (2024-04-01)
^^^^^^^^^^^^^^^^^^^
* expose configuration of ``http_session_cls`` in ``AioConfig``

2.12.1 (2024-03-04)
^^^^^^^^^^^^^^^^^^^
* fix use of proxies #1070

2.12.0 (2024-02-28)
^^^^^^^^^^^^^^^^^^^
* bump botocore dependency specification

2.11.2 (2024-02-02)
^^^^^^^^^^^^^^^^^^^
* bump botocore dependency specification

2.11.1 (2024-01-25)
^^^^^^^^^^^^^^^^^^^
* bump botocore dependency specification

2.11.0 (2024-01-19)
^^^^^^^^^^^^^^^^^^^
* send project-specific `User-Agent` HTTP header #853

2.10.0 (2024-01-18)
^^^^^^^^^^^^^^^^^^^
* bump botocore dependency specification

2.9.1 (2024-01-17)
^^^^^^^^^^^^^^^^^^
* fix race condition in S3 Express identity cache #1072

2.9.0 (2023-12-12)
^^^^^^^^^^^^^^^^^^
* bump botocore dependency specification

2.8.0 (2023-11-28)
^^^^^^^^^^^^^^^^^^
* add AioStubber that returns AioAWSResponse()
* remove confusing `aiobotocore.session.Session` symbol
* bump botocore dependency specification

2.7.0 (2023-10-17)
^^^^^^^^^^^^^^^^^^
* add support for Python 3.12
* drop more Python 3.7 support (EOL)
* relax botocore dependency specification

2.6.0 (2023-08-11)
^^^^^^^^^^^^^^^^^^
* bump aiohttp minimum version to 3.7.4.post0
* drop python 3.7 support (EOL)

2.5.4 (2023-08-07)
^^^^^^^^^^^^^^^^^^
* fix __aenter__ attribute error introduced in refresh bugfix (#1031)

2.5.3 (2023-08-06)
^^^^^^^^^^^^^^^^^^
* add more support for Python 3.11
* bump botocore to 1.31.17
* add waiter.wait return
* fix SSO token refresh bug #1025

2.5.2 (2023-07-06)
^^^^^^^^^^^^^^^^^^
* fix issue #1020

2.5.1 (2023-06-27)
^^^^^^^^^^^^^^^^^^
* bump botocore to 1.29.161

2.5.0 (2023-03-06)
^^^^^^^^^^^^^^^^^^
* bump botocore to 1.29.76 (thanks @jakob-keller #999)

2.4.2 (2022-12-22)
^^^^^^^^^^^^^^^^^^
* fix retries (#988)

2.4.1 (2022-11-28)
^^^^^^^^^^^^^^^^^^
* Adds support for checksums in streamed request trailers (thanks @terrycain #962)

2.4.0 (2022-08-25)
^^^^^^^^^^^^^^^^^^
* bump botocore to 1.27.59

2.3.4 (2022-06-23)
^^^^^^^^^^^^^^^^^^
* fix select_object_content

2.3.3 (2022-06-07)
^^^^^^^^^^^^^^^^^^
* fix connect timeout while getting IAM creds
* fix test files appearing in distribution package

2.3.2 (2022-05-08)
^^^^^^^^^^^^^^^^^^
* fix 3.6 testing and and actually fix 3.6 support

2.3.1 (2022-05-06)
^^^^^^^^^^^^^^^^^^
* fix 3.6 support
* AioConfig: allow keepalive_timeout to be None (thanks @dnlserrano #933)

2.3.0 (2022-05-05)
^^^^^^^^^^^^^^^^^^
* fix encoding issue by swapping to AioAWSResponse and AioAWSRequest to behave more
  like botocore
* fix exceptions mappings

2.2.0 (2022-03-16)
^^^^^^^^^^^^^^^^^^
* remove deprecated APIs
* bump to botocore 1.24.21
* re-enable retry of aiohttp.ClientPayloadError

2.1.2 (2022-03-03)
^^^^^^^^^^^^^^^^^^
* fix httpsession close call

2.1.1 (2022-02-10)
^^^^^^^^^^^^^^^^^^
* implement asynchronous non-blocking adaptive retry strategy

2.1.0 (2021-12-14)
^^^^^^^^^^^^^^^^^^
* bump to botocore 1.23.24
* fix aiohttp resolver config param #906

2.0.1 (2021-11-25)
^^^^^^^^^^^^^^^^^^
* revert accidental dupe of _register_s3_events #867 (thanks @eoghanmurray)
* Support customizing the aiohttp connector resolver class #893 (thanks @orf)
* fix timestream query #902


2.0.0 (2021-11-02)
^^^^^^^^^^^^^^^^^^
* bump to botocore 1.22.8
* turn off default ``AIOBOTOCORE_DEPRECATED_1_4_0_APIS`` env var to match botocore module.  See notes in 1.4.0.

1.4.2 (2021-09-03)
^^^^^^^^^^^^^^^^^^
* Fix missing close() method on http session (thanks `@terrycain <https://github.com/terrycain>`_)
* Fix for verify=False

1.4.1 (2021-08-24)
^^^^^^^^^^^^^^^^^^
* put backwards incompatible changes behind ``AIOBOTOCORE_DEPRECATED_1_4_0_APIS`` env var.  This means that `#876 <https://github.com/aio-libs/aiobotocore/issues/876>`_ will not work unless this env var has been set to 0.

1.4.0 (2021-08-20)
^^^^^^^^^^^^^^^^^^
* fix retries via config `#877 <https://github.com/aio-libs/aiobotocore/pull/877>`_
* remove AioSession and get_session top level names to match botocore_
* change exceptions raised to match those of botocore_, see `mappings <https://github.com/aio-libs/aiobotocore/pull/877/files#diff-b1675e1eb4276bfae81107cda919ba446e4ce1b1e228a9e878d65dd1f474bf8cR162-R181>`_

1.3.3 (2021-07-12)
^^^^^^^^^^^^^^^^^^
* fix AioJSONParser `#872 <https://github.com/aio-libs/aiobotocore/issues/872>`_

1.3.2 (2021-07-07)
^^^^^^^^^^^^^^^^^^
* Bump to botocore_ to `1.20.106 <https://github.com/boto/botocore/tree/1.20.106>`_

1.3.1 (2021-06-11)
^^^^^^^^^^^^^^^^^^
* TCPConnector: change deprecated ssl_context to ssl
* fix non awaited generate presigned url calls `#868 <https://github.com/aio-libs/aiobotocore/issues/868>`_

1.3.0 (2021-04-09)
^^^^^^^^^^^^^^^^^^
* Bump to botocore_ to `1.20.49 <https://github.com/boto/botocore/tree/1.20.49>`_ `#856 <https://github.com/aio-libs/aiobotocore/pull/856>`_

1.2.2 (2021-03-11)
^^^^^^^^^^^^^^^^^^
* Await call to async method _load_creds_via_assume_role `#858 <https://github.com/aio-libs/aiobotocore/pull/858>`_ (thanks `@puzza007 <https://github.com/puzza007>`_)

1.2.1 (2021-02-10)
^^^^^^^^^^^^^^^^^^
* verify strings are now correctly passed to aiohttp.TCPConnector `#851 <https://github.com/aio-libs/aiobotocore/pull/851>`_ (thanks `@FHTMitchell <https://github.com/FHTMitchell>`_)

1.2.0 (2021-01-11)
^^^^^^^^^^^^^^^^^^
* bump botocore to `1.19.52 <https://github.com/boto/botocore/tree/1.19.52>`_
* use passed in http_session_cls param to create_client `#797 <https://github.com/aio-libs/aiobotocore/issues/797>`_

1.1.2 (2020-10-07)
^^^^^^^^^^^^^^^^^^
* fix AioPageIterator search method #831 (thanks `@joseph-jones <https://github.com/joseph-jones>`_)

1.1.1 (2020-08-31)
^^^^^^^^^^^^^^^^^^
* fix s3 region redirect bug #825

1.1.0 (2020-08-18)
^^^^^^^^^^^^^^^^^^
* bump botocore to 1.17.44

1.0.7 (2020-06-04)
^^^^^^^^^^^^^^^^^^
* fix generate_db_auth_token via #816

1.0.6 (2020-06-04)
^^^^^^^^^^^^^^^^^^
* revert __getattr__ fix as it breaks ddtrace

1.0.5 (2020-06-03)
^^^^^^^^^^^^^^^^^^
* Fixed AioSession.get_service_data emit call #811 via #812
* Fixed async __getattr__ #789 via #803

1.0.4 (2020-04-15)
^^^^^^^^^^^^^^^^^^
* Fixed S3 Presigned Post not being async

1.0.3 (2020-04-09)
^^^^^^^^^^^^^^^^^^
* Fixes typo when using credential process

1.0.2 (2020-04-05)
^^^^^^^^^^^^^^^^^^
* Disable Client.__getattr__ emit for now #789

1.0.1 (2020-04-01)
^^^^^^^^^^^^^^^^^^
* Fixed signing requests with explicit credentials

1.0.0 (2020-03-31)
^^^^^^^^^^^^^^^^^^
* API breaking: The result of create_client is now a required async context class
* Credential refresh should now work
* generate_presigned_url is now an async call along with other credential methods
* Credentials.[access_key/secret_key/token] now raise NotImplementedError because
  they won't call refresh like botocore. Instead should use get_frozen_credentials
  async method
* Bump botocore and extras

0.12.0 (2020-02-23)
^^^^^^^^^^^^^^^^^^^
* Bump botocore and extras
* Drop support for 3.5 given we are unable to test it with moto
  and it will soon be unsupported
* Remove loop parameters for Python 3.8 compliance
* Remove deprecated AioPageIterator.next_page

0.11.1 (2020-01-03)
^^^^^^^^^^^^^^^^^^^
* Fixed event streaming API calls like S3 Select.

0.11.0 (2019-11-12)
^^^^^^^^^^^^^^^^^^^
* replace CaseInsensitiveDict with urllib3 equivalent #744
  (thanks to inspiration from @craigmccarter and @kevchentw)
* bump botocore to 1.13.14
* fix for mismatched botocore method replacements

0.10.4 (2019-10-24)
^^^^^^^^^^^^^^^^^^^
* Make AioBaseClient.close method async #724 (thanks @bsitruk)
* Bump awscli, boto3, botocore #735 (thanks @bbrendon)
* switch paginator to async_generator, add result_key_iters
  (deprecate next_page method)

0.10.3 (2019-07-17)
^^^^^^^^^^^^^^^^^^^
* Bump botocore and extras

0.10.2 (2019-02-11)
^^^^^^^^^^^^^^^^^^^
* Fix response-received emitted event #682

0.10.1 (2019-02-08)
^^^^^^^^^^^^^^^^^^^
* Make tests pass with pytest 4.1 #669 (thanks @yan12125)
* Support Python 3.7 #671 (thanks to @yan12125)
* Update RTD build config #672 (thanks @willingc)
* Bump to botocore 1.12.91 #679

0.10.0 (2018-12-09)
^^^^^^^^^^^^^^^^^^^
* Update to botocore 1.12.49 #639 (thanks @terrycain)

0.9.4 (2018-08-08)
^^^^^^^^^^^^^^^^^^
* Add ClientPayloadError as retryable exception

0.9.3 (2018-07-16)
^^^^^^^^^^^^^^^^^^
* Bring botocore up to date

0.9.2 (2018-05-05)
^^^^^^^^^^^^^^^^^^
* bump aiohttp requirement to fix read timeouts

0.9.1 (2018-05-04)
^^^^^^^^^^^^^^^^^^
* fix timeout bug introduced in last release

0.9.0 (2018-06-01)
^^^^^^^^^^^^^^^^^^
* bump aiohttp to 3.3.x
* remove unneeded set_socket_timeout

0.8.0 (2018-05-07)
^^^^^^^^^^^^^^^^^^
* Fix pagination #573 (thanks @adamrothman)
* Enabled several s3 tests via moto
* Bring botocore up to date

0.7.0 (2018-05-01)
^^^^^^^^^^^^^^^^^^
* Just version bump

0.6.1a0 (2018-05-01)
^^^^^^^^^^^^^^^^^^^^
* bump to aiohttp 3.1.x
* switch tests to Python 3.5+
* switch to native coroutines
* fix non-streaming body timeout retries

0.6.0 (2018-03-04)
^^^^^^^^^^^^^^^^^^
* Upgrade to aiohttp>=3.0.0 #536 (thanks @Gr1N)

0.5.3 (2018-02-23)
^^^^^^^^^^^^^^^^^^
* Fixed waiters #523 (thanks @dalazx)
* fix conn_timeout #485

0.5.2 (2017-12-06)
^^^^^^^^^^^^^^^^^^
* Updated awscli dependency #461

0.5.1 (2017-11-10)
^^^^^^^^^^^^^^^^^^
* Disabled compressed response #430

0.5.0 (2017-11-10)
^^^^^^^^^^^^^^^^^^
* Fix error botocore error checking #190
* Update supported botocore requirement to: >=1.7.28, <=1.7.40
* Bump aiohttp requirement to support compressed responses correctly #298

0.4.5 (2017-09-05)
^^^^^^^^^^^^^^^^^^
* Added SQS examples and tests #336
* Changed requirements.txt structure #336
* bump to botocore 1.7.4
* Added DynamoDB examples and tests #340


0.4.4 (2017-08-16)
^^^^^^^^^^^^^^^^^^
* add the supported versions of boto3 to extras require #324

0.4.3 (2017-07-05)
^^^^^^^^^^^^^^^^^^
* add the supported versions of awscli to extras require #273 (thanks @graingert)

0.4.2 (2017-07-03)
^^^^^^^^^^^^^^^^^^
* update supported aiohttp requirement to: >=2.0.4, <=2.3.0
* update supported botocore requirement to: >=1.5.71, <=1.5.78

0.4.1 (2017-06-27)
^^^^^^^^^^^^^^^^^^
* fix redirects #268

0.4.0 (2017-06-19)
^^^^^^^^^^^^^^^^^^
* update botocore requirement to: botocore>=1.5.34, <=1.5.70
* fix read_timeout due to #245
* implement set_socket_timeout

0.3.3 (2017-05-22)
^^^^^^^^^^^^^^^^^^
* switch to PEP 440 version parser to support 'dev' versions

0.3.2 (2017-05-22)
^^^^^^^^^^^^^^^^^^
* Fix botocore integration
* Provisional fix for aiohttp 2.x stream support
* update botocore requirement to: botocore>=1.5.34, <=1.5.52

0.3.1 (2017-04-18)
^^^^^^^^^^^^^^^^^^
* Fixed Waiter support

0.3.0 (2017-04-01)
^^^^^^^^^^^^^^^^^^
* Added support for aiohttp>=2.0.4 (thanks @achimnol)
* update botocore requirement to: botocore>=1.5.0, <=1.5.33

0.2.3 (2017-03-22)
^^^^^^^^^^^^^^^^^^
* update botocore requirement to: botocore>=1.5.0, <1.5.29

0.2.2 (2017-03-07)
^^^^^^^^^^^^^^^^^^
* set aiobotocore.__all__ for * imports #121 (thanks @graingert)
* fix ETag in head_object response #132

0.2.1 (2017-02-01)
^^^^^^^^^^^^^^^^^^
* Normalize headers and handle redirection by botocore #115 (thanks @Fedorof)

0.2.0 (2017-01-30)
^^^^^^^^^^^^^^^^^^
* add support for proxies (thanks @jjonek)
* remove AioConfig verify_ssl connector_arg as this is handled by the
  create_client verify param
* remove AioConfig limit connector_arg as this is now handled by
  by the Config `max_pool_connections` property (note default is 10)

0.1.1 (2017-01-16)
^^^^^^^^^^^^^^^^^^
* botocore updated to version 1.5.0

0.1.0 (2017-01-12)
^^^^^^^^^^^^^^^^^^
* Pass timeout to aiohttp.request to enforce read_timeout #86 (thanks @vharitonsky)
  (bumped up to next semantic version due to read_timeout enabling change)

0.0.6 (2016-11-19)
^^^^^^^^^^^^^^^^^^

* Added enforcement of plain response #57 (thanks @rymir)
* botocore updated to version 1.4.73 #74 (thanks @vas3k)


0.0.5 (2016-06-01)
^^^^^^^^^^^^^^^^^^

* Initial alpha release
