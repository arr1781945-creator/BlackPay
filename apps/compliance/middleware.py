"""
apps/compliance/middleware.py
AuditMiddleware for automatic request logging.
Re-exported from views.py for settings.MIDDLEWARE compatibility.
"""

from apps.compliance.views import AuditMiddleware  # noqa: F401
