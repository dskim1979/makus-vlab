# -*- coding: utf-8 -*-
"""
vLAB (MAKUS) - desktops and shared resources handed out to users.

The vLAB console (separate program, makus-vlab-console) talks only to /api/vlab/*
(pegaprox/api/vlab.py). This package holds the vLAB state (vlab_* tables in the
core DB) and wraps the core functions the console needs, so the console never
depends on the shape of the core API. Design: docs/vlab-design.md.
"""

VLAB_API_VERSION = 1
