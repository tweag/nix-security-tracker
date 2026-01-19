import os

pytest_plugins = ["shared.tests.fixtures"]

# XXX(@fricklerhandwerk): Allows mixing async `live_server` with sync `db` fixtures.
# There seems to be no better way to make that work.
os.environ["DJANGO_ALLOW_ASYNC_UNSAFE"] = "true"
