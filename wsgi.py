"""
WSGI entrypoint for production servers (e.g., Waitress on Windows).

Usage:
  waitress-serve --listen=*:5500 wsgi:application
"""

from app import app as application


