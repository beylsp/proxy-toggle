.PHONY: clean-pyc clean-build clean-test docs clean

help:
	@echo "clean - remove all build, test, coverage, doc and Python artifacts"
	@echo "clean-build - remove build artifacts"
	@echo "clean-test - remove test and coverage artifacts"
	@echo "clean-doc - remove documentation artifacts"
	@echo "clean-pyc - remove Python file artifacts"
	@echo "lint - check style with flake8"
	@echo "test - run tests quickly with the default Python"
	@echo "test-doc - run Sphinx documentation integrity check"
	@echo "test-all - run doc check, check style and run tests on every Python version with tox"
	@echo "coverage - check code coverage quickly with the default Python"
	@echo "coverage-html - generate code coverage HTML report"
	@echo "docs - generate Sphinx HTML documentation, including API docs"

clean: clean-build clean-pyc clean-test clean-doc

clean-build:
	rm -fr build/
	rm -fr dist/
	rm -fr .eggs/
	find . -name '*.egg-info' -exec rm -fr {} +
	find . -name '*.egg' -exec rm -rf {} +

clean-test:
	rm -fr .tox/
	rm -f .coverage
	rm -f coverage.xml
	rm -fr htmlcov/

clean-doc:
	$(MAKE) -C docs clean
	rm -rf docs/proxytoggle*.rst
	rm -rf docs/modules.rst

clean-pyc:
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -fr {} +

lint:
	flake8 -v proxytoggle

test:
	nose2 -v

test-doc:
	sphinx-build -b html -d docs/_build/doctrees docs docs/_build/html

test-all:
	tox

coverage:
	coverage run -m nose2 -v
	coverage report -m

coverage-html: coverage
	coverage html

docs:
	rm -rf docs/proxytoggle*.rst
	rm -rf docs/modules.rst
	sphinx-apidoc -o docs proxytoggle
	$(MAKE) -C docs clean
	$(MAKE) -C docs html	
