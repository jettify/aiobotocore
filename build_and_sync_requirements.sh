#!/usr/bin/env bash

set -xeo pipefail

# This creates a hash from all the files that are used to generate the compiled
# requirements file and then uses that hash to name the output file. This ensures
# that the compiled requirements file always matches sources used to generate it.

function cleanup() {
    trap - EXIT SIGINT SIGTERM
    if [ -f "${scratch_file}" ] ; then
        rm -f "${scratch_file}"
    fi
}

trap cleanup EXIT SIGINT SIGTERM

scratch_file=$(mktemp)

envsubst < requirements-dev.in > ${scratch_file}

# also hash setup.py as it has the install_requires and extras
SHA_SUM=$(sha1sum ${scratch_file} setup.py | head -c 40)
REQUIREMENTS_OUT_FILE=$(echo requirements-dev-python${PYTHON_VERSION}-${SHA_SUM}.txt)

if [ ! -f "${REQUIREMENTS_OUT_FILE}" ] ; then
		time pip-compile requirements-dev.in -o "${REQUIREMENTS_OUT_FILE}"
fi

time pip-sync "${REQUIREMENTS_OUT_FILE}"
