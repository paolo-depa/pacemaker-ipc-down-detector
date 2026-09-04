.PHONY: all venv lint build clean fix

VENV_DIR = .venv
PYTHON = python3
VENV_PYTHON = $(VENV_DIR)/bin/python3
PIP = $(VENV_DIR)/bin/pip

all: lint build

$(VENV_DIR)/bin/activate:
	$(PYTHON) -m venv $(VENV_DIR)
	$(PIP) install --upgrade pip
	$(PIP) install pyinstaller flake8
	touch $(VENV_DIR)/bin/activate

venv: $(VENV_DIR)/bin/activate

lint: venv
	$(VENV_DIR)/bin/flake8 --max-line-length=150 src/ bin/pacemaker-push-diagnostics

build: venv
	$(VENV_DIR)/bin/pyinstaller --noconfirm --onefile --console --name pacemaker-push-diagnostics \
		--paths src \
		bin/pacemaker-push-diagnostics

clean:
	rm -rf $(VENV_DIR) build/ dist/ pacemaker-push-diagnostics.spec
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

fix:
	find src/ bin/ -type f -name "*.py" -exec sed -i 's/[[:space:]]*$$//' {} +
	sed -i 's/[[:space:]]*$$//' bin/pacemaker-push-diagnostics
