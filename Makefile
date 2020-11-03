# Some simple testing tasks (sorry, UNIX only).

FLAGS=

LIB=aiobotocore

# the install uses conda to provide a python 3.6 base environment;
# the init.sh script uses a reliable conda environment to do so.
init: poetry
	./init.sh

flake: package-check
	@poetry run python3 -m flake8 --format=abspath

test: flake
	@poetry run python3 -Wd -m pytest -s -vv $(FLAGS) ./tests/

vtest:
	@poetry run python3 -Wd -X tracemalloc=5 -X faulthandler -m pytest -s -vv $(FLAGS) ./tests/

cov cover coverage: flake
	@poetry run python3 -Wd -m pytest -s -vv --cov-report term --cov-report html --cov $(LIB) ./tests
	@echo "open file://`pwd`/htmlcov/index.html"

# BOTO_CONFIG solves https://github.com/travis-ci/travis-ci/issues/7940
mototest:
	BOTO_CONFIG=/dev/null poetry run python3 -Wd -X tracemalloc=5 -X faulthandler -m pytest -vv -m moto -n auto --cov-report term --cov-report html --cov $(LIB) tests
	@echo "open file://`pwd`/htmlcov/index.html"

clean:
	find . -name __pycache__ -exec rm -rf {} +
	find . -type f -name '*.py[co]' -exec rm -f {} +
	find . -type f -name '*~' -exec rm -f {} +
	find . -type f -name '.*~' -exec rm -f {} +
	find . -type f -name '@*' -exec rm -f {} +
	find . -type f -name '#*#' -exec rm -f {} +
	find . -type f -name '*.orig' -exec rm -f {} +
	find . -type f -name '*.rej' -exec rm -f {} +
	rm -f .coverage
	rm -rf coverage
	rm -rf build
	rm -rf cover
	rm -rf dist

doc:
	make -C docs html
	@echo "open file://`pwd`/docs/_build/html/index.html"

typehint: clean
	@poetry run mypy --follow-imports=skip $(LIB) tests

package: clean
	@poetry check
	@poetry build

package-check: package
	@poetry run twine check dist/*

poetry:
	@if ! command -v poetry > /dev/null; then \
		curl -sSL https://raw.githubusercontent.com/sdispater/poetry/master/get-poetry.py -o /tmp/get-poetry.py; \
		python /tmp/get-poetry.py; \
	fi

poetry-export:
	poetry export --without-hashes -f requirements.txt -o requirements.txt
	sed -i -e 's/^-e //g' requirements.txt


.PHONY: init typehint package package-check poetry poetry-export
.PHONY: all flake test vtest cov clean doc
