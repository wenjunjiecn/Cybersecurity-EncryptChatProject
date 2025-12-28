.PHONY: install server client clean run

# Default python interpreter
PYTHON = python3

install:
	pip install -r requirements.txt

server:
	$(PYTHON) Server.py

client:
	$(PYTHON) Client.py

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

# Helper to run both (for development, might require backgrounding manually in some environments)
# This is a bit tricky in a Makefile as make waits for the first command to finish.
# We'll just document the separate commands.
