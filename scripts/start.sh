#!/bin/bash

uv run celery -A src worker --loglevel=INFO &

uv run fastapi run src/main.py
