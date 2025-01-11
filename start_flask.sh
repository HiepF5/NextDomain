#!/bin/bash

# Activate virtual environment
source ./venv/bin/activate

# Export environment variables
export FLASK_CONF=../configs/production.py
export FLASK_APP=powerdnsadmin/__init__.py

# Run database migrations
flask db upgrade

# Install frontend dependencies and build assets
yarn install --pure-lockfile
flask assets build

# Start the Flask application
python ./run.py
