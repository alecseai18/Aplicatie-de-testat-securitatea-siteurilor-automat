from __future__ import annotations

import json
import time
import uuid
from typing import Callable


DEFAULT_QUEUE = 'ctf.scan.jobs'


class QueueingError(RuntimeError):
    pass


def _load_pika():
    try:
        import pika
    except ImportError as exc:
        raise QueueingError('RabbitMQ support requires pika. Run: pip install -r requirements.txt') from exc
    return pika


def publish_scan_job(scan_options: dict, rabbitmq_url: str, queue_name: str = DEFAULT_QUEUE) -> str:
    pika = _load_pika()
    job_id = uuid.uuid4().hex
    body = {
        'job_id': job_id,
        'created_at': int(time.time()),
        'scan': scan_options,
    }

    connection = pika.BlockingConnection(pika.URLParameters(rabbitmq_url))
    try:
        channel = connection.channel()
        channel.queue_declare(queue=queue_name, durable=True)
        channel.basic_publish(
            exchange='',
            routing_key=queue_name,
            body=json.dumps(body).encode('utf-8'),
            properties=pika.BasicProperties(
                content_type='application/json',
                delivery_mode=2,
            ),
        )
    finally:
        connection.close()
    return job_id


def consume_scan_jobs(
    handler: Callable[[dict], None],
    rabbitmq_url: str,
    queue_name: str = DEFAULT_QUEUE,
    prefetch: int = 1,
    log: Callable[[str], None] = print,
) -> None:
    pika = _load_pika()
    connection = pika.BlockingConnection(pika.URLParameters(rabbitmq_url))
    channel = connection.channel()
    channel.queue_declare(queue=queue_name, durable=True)
    channel.basic_qos(prefetch_count=max(1, prefetch))

    def callback(ch, method, properties, body):
        try:
            payload = json.loads(body.decode('utf-8'))
            handler(payload)
        except Exception as exc:
            log(f'[!] Job failed and will not be requeued: {type(exc).__name__}: {exc}')
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
            return
        ch.basic_ack(delivery_tag=method.delivery_tag)

    channel.basic_consume(queue=queue_name, on_message_callback=callback, auto_ack=False)
    log(f'[+] Waiting for RabbitMQ scan jobs on queue {queue_name}. Press Ctrl+C to stop.')
    try:
        channel.start_consuming()
    except KeyboardInterrupt:
        log('[!] Worker stopped by user.')
        channel.stop_consuming()
    finally:
        connection.close()
