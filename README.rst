aiobotocore
===========
.. |ci badge| image:: https://github.com/aio-libs/aiobotocore/actions/workflows/ci-cd.yml/badge.svg?branch=master
    :target: https://github.com/aio-libs/aiobotocore/actions/workflows/ci-cd.yml
    :alt: CI status of master branch
.. |pre-commit badge| image:: https://results.pre-commit.ci/badge/github/aio-libs/aiobotocore/master.svg
    :target: https://results.pre-commit.ci/latest/github/aio-libs/aiobotocore/master
    :alt: pre-commit.ci status
.. |coverage badge| image:: https://codecov.io/gh/aio-libs/aiobotocore/branch/master/graph/badge.svg
    :target: https://codecov.io/gh/aio-libs/aiobotocore
    :alt: Coverage status on master branch
.. |docs badge| image:: https://readthedocs.org/projects/aiobotocore/badge/?version=latest
    :target: https://aiobotocore.readthedocs.io/en/latest/?badge=latest
    :alt: Documentation Status
.. |pypi badge| image:: https://img.shields.io/pypi/v/aiobotocore.svg
    :target: https://pypi.python.org/pypi/aiobotocore
    :alt: Latest version on pypi
.. |gitter badge| image:: https://badges.gitter.im/Join%20Chat.svg
    :target: https://gitter.im/aio-libs/aiobotocore
    :alt: Chat on Gitter
.. |pypi downloads badge| image:: https://img.shields.io/pypi/dm/aiobotocore.svg?label=PyPI%20downloads
    :target: https://pypi.org/project/aiobotocore/
    :alt: Downloads Last Month
.. |conda badge| image:: https://img.shields.io/conda/dn/conda-forge/aiobotocore.svg?label=Conda%20downloads
    :target: https://anaconda.org/conda-forge/aiobotocore
    :alt: Conda downloads
.. |stackoverflow badge| image:: https://img.shields.io/badge/stackoverflow-Ask%20questions-blue.svg
    :target: https://stackoverflow.com/questions/tagged/aiobotocore
    :alt: Stack Overflow

|ci badge| |pre-commit badge| |coverage badge| |docs badge| |pypi badge| |gitter badge| |pypi downloads badge| |conda badge| |stackoverflow badge|

Async client for amazon services using botocore_ and aiohttp_/asyncio_.

This library is a mostly full featured asynchronous version of botocore.


Install
-------
::

    $ pip install aiobotocore


Basic Example
-------------

.. code:: python

    import asyncio
    from aiobotocore.session import get_session

    AWS_ACCESS_KEY_ID = "xxx"
    AWS_SECRET_ACCESS_KEY = "xxx"


    async def go():
        bucket = 'dataintake'
        filename = 'dummy.bin'
        folder = 'aiobotocore'
        key = '{}/{}'.format(folder, filename)

        session = get_session()
        async with session.create_client('s3', region_name='us-west-2',
                                       aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                                       aws_access_key_id=AWS_ACCESS_KEY_ID) as client:
            # upload object to amazon s3
            data = b'\x01'*1024
            resp = await client.put_object(Bucket=bucket,
                                                Key=key,
                                                Body=data)
            print(resp)

            # getting s3 object properties of file we just uploaded
            resp = await client.get_object_acl(Bucket=bucket, Key=key)
            print(resp)

            # get object from s3
            response = await client.get_object(Bucket=bucket, Key=key)
            # this will ensure the connection is correctly re-used/closed
            async with response['Body'] as stream:
                assert await stream.read() == data

            # list s3 objects using paginator
            paginator = client.get_paginator('list_objects')
            async for result in paginator.paginate(Bucket=bucket, Prefix=folder):
                for c in result.get('Contents', []):
                    print(c)

            # delete object from s3
            resp = await client.delete_object(Bucket=bucket, Key=key)
            print(resp)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(go())



Context Manager Examples
------------------------

.. code:: python

    from contextlib import AsyncExitStack

    from aiobotocore.session import AioSession


    # How to use in existing context manager
    class Manager:
        def __init__(self):
            self._exit_stack = AsyncExitStack()
            self._s3_client = None

        async def __aenter__(self):
            session = AioSession()
            self._s3_client = await self._exit_stack.enter_async_context(session.create_client('s3'))

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            await self._exit_stack.__aexit__(exc_type, exc_val, exc_tb)

    # How to use with an external exit_stack
    async def create_s3_client(session: AioSession, exit_stack: AsyncExitStack):
        # Create client and add cleanup
        client = await exit_stack.enter_async_context(session.create_client('s3'))
        return client


    async def non_manager_example():
        session = AioSession()

        async with AsyncExitStack() as exit_stack:
            s3_client = await create_s3_client(session, exit_stack)

            # do work with s3_client



Supported AWS Services
----------------------

This is a non-exuastive list of what tests aiobotocore runs against AWS services. Not all methods are tested but we aim to test the majority of
commonly used methods.

+----------------+-----------------------+
| Service        | Status                |
+================+=======================+
| S3             | Working               |
+----------------+-----------------------+
| DynamoDB       | Basic methods tested  |
+----------------+-----------------------+
| SNS            | Basic methods tested  |
+----------------+-----------------------+
| SQS            | Basic methods tested  |
+----------------+-----------------------+
| CloudFormation | Stack creation tested |
+----------------+-----------------------+
| Kinesis        | Basic methods tested  |
+----------------+-----------------------+

Due to the way boto3 is implemented, its highly likely that even if services are not listed above that you can take any ``boto3.client('service')`` and
stick ``await`` in front of methods to make them async, e.g. ``await client.list_named_queries()`` would asynchronous list all of the named Athena queries.

If a service is not listed here and you could do with some tests or examples feel free to raise an issue.

Run Tests
---------

There are two set of tests, those that can be mocked through `moto <https://github.com/getmoto/moto>`_ running in docker, and those that require running against a personal amazon key. The CI only runs the moto tests.

To run the moto tests:

::

    $ make mototest

To run the non-moto tests:

Make sure you have development requirements installed and your amazon key and
secret accessible via environment variables:

::

    $ pip install pip-tools
    $ pip-compile --all-extras pyproject.toml
    $ pip-sync
    $ pip install -e ".[awscli,boto3]"
    $ export AWS_ACCESS_KEY_ID=xxx
    $ export AWS_SECRET_ACCESS_KEY=xxx
    $ export AWS_DEFAULT_REGION=xxx # e.g. us-west-2

Execute tests suite:

::

    $ make test



Enable type checking and code completion
----------------------------------------

Install types-aiobotocore_ that contains type annotations for ``aiobotocore``
and all supported botocore_ services.

.. code:: bash

    # install aiobotocore type annotations
    # for ec2, s3, rds, lambda, sqs, dynamo and cloudformation
    python -m pip install 'types-aiobotocore[essential]'

    # or install annotations for services you use
    python -m pip install 'types-aiobotocore[acm,apigateway]'

    # Lite version does not provide session.create_client overloads
    # it is more RAM-friendly, but requires explicit type annotations
    python -m pip install 'types-aiobotocore-lite[essential]'

Now you should be able to run Pylance_, pyright_, or mypy_ for type checking
as well as code completion in your IDE.

For ``types-aiobotocore-lite`` package use explicit type annotations:

.. code:: python

    from aiobotocore.session import get_session
    from types_aiobotocore_s3.client import S3Client

    session = get_session()
    async with session.create_client("s3") as client:
        client: S3Client
        # type checking and code completion is now enabled for client


Full documentation for ``types-aiobotocore`` can be found here: https://youtype.github.io/types_aiobotocore_docs/


Requirements
------------
* Python_ 3.8+
* aiohttp_
* botocore_

.. _Python: https://www.python.org
.. _asyncio: https://docs.python.org/3/library/asyncio.html
.. _botocore: https://github.com/boto/botocore
.. _aiohttp: https://github.com/aio-libs/aiohttp
.. _types-aiobotocore: https://youtype.github.io/types_aiobotocore_docs/
.. _Pylance: https://marketplace.visualstudio.com/items?itemName=ms-python.vscode-pylance
.. _pyright: https://github.com/microsoft/pyright
.. _mypy: http://mypy-lang.org/

awscli & boto3
--------------

awscli and boto3 depend on a single version, or a narrow range of versions, of botocore.
However, aiobotocore only supports a specific range of botocore versions. To ensure you
install the latest version of awscli and boto3 that your specific combination or
aiobotocore and botocore can support use::

    pip install -U 'aiobotocore[awscli,boto3]'

If you only need awscli and not boto3 (or vice versa) you can just install one extra or
the other.
