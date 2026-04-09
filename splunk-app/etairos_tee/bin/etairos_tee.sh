#!/bin/sh
# Portable launcher — works on Linux, macOS, and Windows (via Git Bash)
# SPLUNK_HOME is set by Splunk before calling scripted inputs

SPLUNK_HOME="${SPLUNK_HOME:-/opt/splunkforwarder}"
APP_DIR="${SPLUNK_HOME}/etc/apps/etairos_tee"

exec "${SPLUNK_HOME}/bin/splunk" cmd python3 "${APP_DIR}/bin/start_listener.py"
