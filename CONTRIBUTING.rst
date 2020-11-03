Contributing
============

Running Tests
-------------

.. _GitHub: https://github.com/aio-libs/aiobotocore

Thanks for your interest in contributing to ``aiobotocore``, there are multiple
ways and places you can contribute.

Fist of all just clone repository::

    $ git clone git@github.com:aio-libs/aiobotocore.git

Create virtualenv with at least python3.5 (older version are not supported).
For example using *virtualenvwrapper* commands could look like::

   $ cd aiobotocore
   $ make init

The virtualenv is provided by a conda installation and the project
dependencies are installed by poetry.  See the `Makefile` and the
`init.sh` script for details.  The `make init` script is designed
to be run only when a clean virtualenv is created; after that, the
virtualenv is usually only activated and packages are managed using
poetry.

Congratulations, you are ready to run the test suite::

    $ make cov

To run individual use following command::

    $ py.test -sv tests/test_monitor.py -k test_name


Reporting an Issue
------------------
If you have found issue with `aiobotocore` please do
not hesitate to file an issue on the GitHub_ project. When filing your
issue please make sure you can express the issue with a reproducible test
case.

When reporting an issue we also need as much information about your environment
that you can include. We never know what information will be pertinent when
trying narrow down the issue. Please include at least the following
information:

* Version of `aiobotocore` and `python`.
* Version fo `botocore`.
* Platform you're running on (OS X, Linux).


Background and Implementation
-----------------------------
aiobotocore adds async functionality to botocore by replacing certain critical
methods in botocore classes with async versions.  The best way to see how this
works is by working backwards from `AioEndpoint._request`.  Because of this tight
integration aiobotocore is typically version locked to a particular release of
botocore.

How to Upgrade Botocore
-----------------------
aiobotocore's file names try to match the botocore files they functionally match.
For the most part botocore classes are sub-classed with the majority of the
botocore calls eventually called.

The best way I've seen to upgrade botocore support is by downloading the sources
of the release of botocore you're trying to upgrade to, and the version
of botocore that aiobotocore is currently locked to and do a folder based file
comparison (tools like DiffMerge are nice). You can then manually apply the
relevant changes to their aiobotocore equivalent(s). In order to support a range
of versions one would need validate the version each change was introduced and
select the newest of these to the current version.  This is further complicated
by the aiobotocore "extras" requirements which need to be updated to the
versions that are compatible with the above changes.

See next section describing types of changes we must validate and support.

Hashes of Botocore Code (important)
-----------------------------------
Because of the way aiobotocore is implemented (see Background section), it is very tightly coupled with botocore.  The validity of these couplings are enforced in test_patches.py.  We also depend on some private properties in aiohttp, and because of this have entries in test_patches.py for this too.

These patches are important to catch cases where botocore functionality was added/removed and needs to be reflected in our overridden methods.  Changes include:

* parameters to methods added/removed
* classes/methods being moved to new files
* bodies of overridden methods updated

To ensure we catch and reflect this changes in aiobotocore, the test_patches.py file has the hashes of the parts of botocore we need to manually validate changes in.

test_patches.py file needs to be updated in two scenarios:

1. You're bumping the supported botocore/aiohttp version. In this case a failure in test_patches.py means you need to validate the section of code in aiohttp/botocore that no longer matches the hash in test_patches.py to see if any changes need to be reflected in aiobotocore which overloads, on depends on the code which triggered the hash mismatch.  This could there are new parameters we weren't expecting, parameters that are no longer passed to said overriden function(s), or an overridden function which calls a modified botocore method.  If this is a whole class collision the checks will be more extensive.
2. You're implementing missing aiobotocore functionality, in which case you need to add entries for all the methods in botocore/aiohttp which you are overriding or depending on private functionality.  For special cases, like when private attributes are used, you may have to hash the whole class so you can catch any case where the private property is used/updated to ensure it matches our expectations.

After you've validated the changes, you can update the hash in test_patches.py.

One would think we could just write enough unittests to catch all cases, however, this is impossible for two reasons:

1. We do not support all botocore unittests, for future work see discussion: https://github.com/aio-libs/aiobotocore/issues/213
2. Even if we did all the unittests from 1, we would not support NEW functionality added, unless we automatically pulled all new unittests as well from botocore.

Until we can perform ALL unittests from new releases of botocore, we are stuck with the patches.


The Future
----------
The long term goal is that botocore will implement async functionality directly.
See botocore issue: https://github.com/boto/botocore/issues/458  for details,
tracked in aiobotocore here: https://github.com/aio-libs/aiobotocore/issues/36
