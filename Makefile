# Some simple testing tasks (sorry, UNIX only).

FLAGS?=
# ?= is assignment conditional on it not being set
HTTP_BACKEND?='all'

pre-commit flake: checkrst
	pre-commit run --all

test: pre-commit
	python -Wd -m pytest -s -vv $(FLAGS) ./tests/

vtest:
	python -Wd -X tracemalloc=5 -X faulthandler -m pytest -s -vv $(FLAGS) ./tests/

checkrst:
	python setup.py check -rms

cov cover coverage: pre-commit
	python -Wd -m pytest -s -vv --cov-report term --cov-report html --cov aiobotocore ./tests
	@echo "open file://`pwd`/htmlcov/index.html"

# BOTO_CONFIG solves https://github.com/travis-ci/travis-ci/issues/7940
mototest:
	docker pull alpine
	docker pull lambci/lambda:python3.8
	BOTO_CONFIG=/dev/null python -Wd -X tracemalloc=5 -X faulthandler -m pytest -vv -m moto -n auto --cov-report term --cov-report html --cov-report xml --cov=aiobotocore --cov=tests --log-cli-level=DEBUG --http-backend=$(HTTP_BACKEND) $(FLAGS) aiobotocore tests
	@echo "open file://`pwd`/htmlcov/index.html"

clean:
	rm -rf `find . -name __pycache__`
	rm -rf `find . -name .pytest_cache`
	rm -rf `find . -name *.egg-info`
	rm -f `find . -type f -name '*.py[co]' `
	rm -f `find . -type f -name '*~' `
	rm -f `find . -type f -name '.*~' `
	rm -f `find . -type f -name '@*' `
	rm -f `find . -type f -name '#*#' `
	rm -f `find . -type f -name '*.orig' `
	rm -f `find . -type f -name '*.rej' `
	rm -f .coverage*
	rm -rf coverage
	rm -rf coverage.xml
	rm -rf htmlcov
	rm -rf build
	rm -rf cover
	rm -rf dist

doc:
	make -C docs html
	@echo "open file://`pwd`/docs/_build/html/index.html"

.PHONY: all pre-commit test vtest cov clean doc
