from __future__ import annotations

import os

from .env import load_local_env
from .queueing import consume_scan_jobs
from .scanner import Scanner


SCANNER_KEYS = {
    'base_url',
    'username',
    'password',
    'workers',
    'depth',
    'aggressive',
    'confirm_only',
    'timeout',
    'ai',
    'ai_model',
    'ai_concurrency',
    'ai_max_findings',
    'ai_max_output_tokens',
    'ai_skip_overviews',
}


def run_worker(
    rabbitmq_url: str,
    queue_name: str,
    default_report_dir: str = 'reports',
    prefetch: int = 1,
) -> None:
    load_local_env()

    def handle_job(payload: dict) -> None:
        job_id = str(payload.get('job_id') or 'manual-job')
        scan = dict(payload.get('scan') or {})
        options = {key: scan[key] for key in SCANNER_KEYS if key in scan}
        missing = [key for key in ('base_url',) if not options.get(key)]
        if missing:
            raise ValueError(f'missing required scan option(s): {", ".join(missing)}')

        report_root = scan.get('report_dir') or default_report_dir
        options['report_dir'] = os.path.join(report_root, job_id)
        print(f'[+] Starting queued scan job {job_id}: {options["base_url"]}')
        Scanner(**options).run()
        print(f'[+] Finished queued scan job {job_id}: {options["report_dir"]}')

    consume_scan_jobs(
        handler=handle_job,
        rabbitmq_url=rabbitmq_url,
        queue_name=queue_name,
        prefetch=prefetch,
    )
