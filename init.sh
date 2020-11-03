#!/bin/bash

export CONDA_ENV="aiobotocore"

# shellcheck disable=SC1091
source ./conda_venv.sh

if ! command -v conda > /dev/null; then
    conda-install
fi

# Assume conda is already installed correctly and
# source the conda config file from the usual paths
# shellcheck disable=SC1091,SC1090
source /etc/profile.d/conda.sh || \
    source /opt/conda/etc/profile.d/conda.sh || \
    source ~/miniconda3/etc/profile.d/conda.sh || \
    source ~/opt/anaconda3/etc/profile.d/conda.sh

conda-venv 3.6
command -v python
python --version
python -m pip install --upgrade pip

if ! command -v poetry > /dev/null; then
  curl -sSL https://raw.githubusercontent.com/sdispater/poetry/master/get-poetry.py | python
fi

# install dev-deps before the poetry project installation, so
# that the project dependencies can override the dev-deps.
if [ -f requirements.dev ]; then
  poetry run python -m pip install -r requirements.dev
  poetry run pre-commit install
  # pip does not fully resolve conflicts, it just warns about them;
  # use pip check to identify conflicts; some of them may not be
  # important but others may need to be fixed somehow
  poetry run python -m pip check
fi

# for development, install all the extras
poetry install -v --no-interaction --extras all

echo "To activate environment, execute 'conda activate ${CONDA_ENV}'"
