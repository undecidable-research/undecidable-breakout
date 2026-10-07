"""Read-only web frontend over the corpus, the profiles and the reports on disk.

Same five greys, same type, same rings as report.html. Every page has a JSON twin
for agents (Accept: application/json, ?format=json, or /api/<path>). Stdlib only.
"""
from .server import handle, make_server, serve
from .views import Site

__all__ = ["Site", "handle", "make_server", "serve"]
