Contributing
============

Running Tests
-------------

.. _GitHub: https://github.com/aio-libs/aiobotocore

Thanks for your interest in contributing to ``aiobotocore``, there are multiple
ways and places you can contribute.

First of all, clone the repository::

    $ git clone git@github.com:aio-libs/aiobotocore.git

Make sure the Python package and project manager `uv <https://docs.astral.sh/uv/>`_ is installed.

Create a virtual environment::

    $ cd aiobotocore
    $ uv venv

Install pre-commit hooks::

    $ uv run pre-commit install

Congratulations, you are ready to run the test suite.

There are two set of tests, those that can be mocked through `moto <https://github.com/getmoto/moto>`_ running in docker, and those that require running against a personal amazon key. The CI only runs the moto tests.

To run the moto tests::

    $ uv run make mototest

To run the non-moto tests, make sure you have your amazon key and secret accessible via environment variables::

    $ export AWS_ACCESS_KEY_ID=xxx
    $ export AWS_SECRET_ACCESS_KEY=xxx
    $ export AWS_DEFAULT_REGION=xxx # e.g. us-west-2

Execute full tests suite::

    $ uv run make test

Execute full tests suite with coverage::

    $ uv run make cov

To run individual use following command::

    $ uv run pytest -sv tests/test_monitor.py -k test_name


Reporting an Issue
------------------
If you have found issue with ``aiobotocore`` please do
not hesitate to file an issue on the GitHub_ project. When filing your
issue please make sure you can express the issue with a reproducible test
case.

When reporting an issue we also need as much information about your environment
that you can include. We never know what information will be pertinent when
trying narrow down the issue. Please include at least the following
information:

* Version of ``aiobotocore`` and ``python``.
* Version of ``botocore``.
* Platform you're running on (OS X, Linux).


Background and Implementation
-----------------------------
aiobotocore adds async functionality to botocore by replacing certain critical
methods in botocore classes with async versions.  The best way to see how this
works is by working backwards from ``AioEndpoint._request``.  Because of this tight
integration aiobotocore is typically version locked to a particular release of
botocore.

How to Upgrade Botocore
-----------------------
aiobotocore's file names, and ordering of functions in files try to match the botocore files they override.
For the most part botocore classes are sub-classed with the majority of the
botocore calls eventually called.

The best way I've seen to upgrade botocore support is by performing the following:

1. Download sources of the release of botocore you're trying to upgrade to, and the version of botocore that aiobotocore is currently locked to (see :file:`pyproject.toml`) and do a folder based file comparison of the botocore folders (tools like DiffMerge are nice).
2. Manually apply the relevant changes to their aiobotocore equivalent(s). Note that sometimes new functions are added which will need to be overridden (like ``__enter__`` -> ``__aenter__``)
3. Update the "project.optional-dependencies" in :file:`pyproject.toml` to the versions which match the botocore version you are targeting.
4. Now do a directory diff between aiobotocore and your target version botocore directory to ensure the changes were propagated.

See next section describing types of changes we must validate and support.

Hashes of Botocore Code (important)
-----------------------------------
Because of the way aiobotocore is implemented (see Background section), it is very tightly coupled with botocore.  The validity of these couplings are enforced in :file:`test_patches.py`.  We also depend on some private properties in aiohttp, and because of this have entries in :file:`test_patches.py` for this too.

These patches are important to catch cases where botocore functionality was added/removed and needs to be reflected in our overridden methods.  Changes include:

* parameters to methods added/removed
* classes/methods being moved to new files
* bodies of overridden methods updated

To ensure we catch and reflect this changes in aiobotocore, the :file:`test_patches.py` file has the hashes of the parts of botocore we need to manually validate changes in.

:file:`test_patches.py` file needs to be updated in two scenarios:

1. You're bumping the supported botocore/aiohttp version. In this case a failure in :file:`test_patches.py` means you need to validate the section of code in aiohttp/botocore that no longer matches the hash in test_patches.py to see if any changes need to be reflected in aiobotocore which overloads, on depends on the code which triggered the hash mismatch.  This could there are new parameters we weren't expecting, parameters that are no longer passed to said overridden function(s), or an overridden function which calls a modified botocore method.  If this is a whole class collision the checks will be more extensive.
2. You're implementing missing aiobotocore functionality, in which case you need to add entries for all the methods in botocore/aiohttp which you are overriding or depending on private functionality.  For special cases, like when private attributes are used, you may have to hash the whole class so you can catch any case where the private property is used/updated to ensure it matches our expectations.

After you've validated the changes, you can update the hash in :file:`test_patches.py`.

One would think we could just write enough unittests to catch all cases, however, this is impossible for two reasons:

1. We do not support all botocore unittests, for future work see discussion: https://github.com/aio-libs/aiobotocore/issues/213
2. Even if we did all the unittests from 1, we would not support NEW functionality added, unless we automatically pulled all new unittests as well from botocore.

Until we can perform ALL unittests from new releases of botocore, we are stuck with the patches.


The Future
----------
The long term goal is that botocore will implement async functionality directly.
See botocore issue: https://github.com/boto/botocore/issues/458  for details,
tracked in aiobotocore here: https://github.com/aio-libs/aiobotocore/issues/36
