PYTHON_VER			:= 3.11.5
VENV				:= $(PYTHON_VER)-template

test_all:
	@if [ -e htmlcov ]; then\
		(rm -r htmlcov) \
	fi
	( \
		export SQLALCHEMY_WARN_20=1 && \
		pytest -n 8 -c tests/pytest.ini -v --dist=loadgroup --cov --cov-report=xml --cov-report=html --junitxml=xunit-result.xml tests \
	)

test: __require_target__
	( \
		export SQLALCHEMY_WARN_20=1 && \
		pytest -v $(TARGET) --cov --cov-report=xml --cov-report=html --junitxml=xunit-result.xml \
	)

env/init: virtualenv/install python/requirements

env/destroy: virtualenv/remove

env/upgrade:
	( \
		export PIP_CONSTRAINT='constraints.txt' && \
		. ~/.pyenv/versions/$(VENV)/bin/activate && \
		python -m pip install --upgrade pip && \
		pip install pip-review && \
		pip-review -i && \
		pip uninstall -y pip-review \
	)

env/freeze:
	( \
		. ~/.pyenv/versions/$(VENV)/bin/activate && \
		pip freeze \
	)

virtualenv/install:
	$(eval ret := $(shell pyenv versions | grep $(PYTHON_VER)))
	@if [ -n "$(ret)" ]; then \
		echo '$(PYTHON_VER) exists'; \
	else \
		(pyenv install $(PYTHON_VER)); \
	fi
	$(eval ret := $(shell pyenv versions | grep -P "\s$(VENV)(?=\s|$$)"))
	@if [ -n "$(ret)" ]; then \
		echo '$(VENV) exists'; \
	else \
		(pyenv virtualenv -f $(PYTHON_VER) $(VENV)); \
	fi
	pyenv versions

virtualenv/remove:
	(pyenv uninstall -f $(VENV))

python/requirements:
	$(eval TMP := $(shell mktemp -d))
	( \
		. ~/.pyenv/versions/$(VENV)/bin/activate && \
		python -m pip install --upgrade pip && \
		pip install -r dev_requirements.txt && \
		pip install -r requirements.txt \
	)
	( \
		. ~/.pyenv/versions/$(VENV)/bin/activate && \
		pip freeze \
	)

__require_target__:
	@[ -n "$(TARGET)" ] || (echo "[ERROR] Parameter [TARGET] is requierd" 1>&2 && echo "(e.g) make xxx TARGET=..." 1>&2 && exit 1)

