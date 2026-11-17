"""Offline stand-in for python-dotenv: tests must never load a real .env file."""


def load_dotenv(*args, **kwargs):
    return False
