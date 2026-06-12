#!/bin/bash
# One-time: create a WSL venv with the anthropic SDK for the live kdb agent.
set -e
python3 -m venv "$HOME/aegis-venv"
"$HOME/aegis-venv/bin/pip" -q install --upgrade pip
"$HOME/aegis-venv/bin/pip" -q install anthropic
echo "--- check ---"
"$HOME/aegis-venv/bin/python" -c "import anthropic; print('anthropic', anthropic.__version__)"
