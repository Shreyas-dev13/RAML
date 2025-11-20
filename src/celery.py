import os
import asyncio
import functools

from celery import Celery

app = Celery(
    'tasks',
    broker=os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379'),
    backend=os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379'),
    include=['src.services.raml_service']
)

def schedule_task(coro):
    """Decorator to schedule an async function as a Celery task."""
    @app.task
    @functools.wraps(coro)
    def wrapper(*args, **kwargs):
        return asyncio.run(coro(*args, **kwargs))

    return wrapper
