from __future__ import annotations

import argparse
import os
import sys
from typing import Sequence

from .env import load_local_env
from .queueing import QueueingError, publish_scan_job


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='CTF aggressive local web pentest scanner')
    parser.add_argument('--gui', action='store_true', help='Launch the desktop GUI')
    parser.add_argument('--base-url')
    parser.add_argument('--username', default='admin')
    parser.add_argument('--password', default='admin123')
    parser.add_argument('--workers', type=int, default=60)
    parser.add_argument('--depth', type=int, default=4)
    parser.add_argument('--aggressive', action='store_true')
    parser.add_argument('--confirm-only', action='store_true')
    parser.add_argument('--mode', default='ctf')
    parser.add_argument('--timeout', type=float, default=4.0)
    parser.add_argument('--report-dir', default=os.getenv('SCANNER_REPORT_DIR', 'reports'))
    parser.add_argument('--ai', action='store_true', help='Generate AI-enhanced analysis using Gemini API key from GEMINI_API_KEY/GOOGLE_API_KEY')
    parser.add_argument('--ai-model', default='gemini-3-flash-preview', help='Gemini model used for AI remediation reports')
    parser.add_argument('--ai-api-key', default='', help='Gemini API key for this local run. Prefer GEMINI_API_KEY for normal use.')
    parser.add_argument('--ai-concurrency', type=int, default=4, help='Parallel Gemini calls for per-finding analysis')
    parser.add_argument('--ai-max-findings', type=int, default=0, help='Only analyze the top N findings with AI; 0 means all findings')
    parser.add_argument('--ai-max-output-tokens', type=int, default=2048, help='Maximum Gemini output tokens per AI call')
    parser.add_argument('--ai-skip-overviews', action='store_true', help='Skip executive_summary.md and developer_checklist.md AI calls for faster runs')
    parser.add_argument('--queue-job', action='store_true', help='Publish this scan as a durable RabbitMQ job instead of running it locally')
    parser.add_argument('--worker', action='store_true', help='Consume scan jobs from RabbitMQ')
    parser.add_argument('--rabbitmq-url', default=os.getenv('RABBITMQ_URL', 'amqp://guest:guest@localhost:5672/%2F'))
    parser.add_argument('--queue-name', default=os.getenv('SCANNER_QUEUE', 'ctf.scan.jobs'))
    parser.add_argument('--prefetch', type=int, default=1, help='RabbitMQ worker prefetch count')
    return parser


def scan_options_from_args(args: argparse.Namespace) -> dict:
    return {
        'base_url': args.base_url,
        'username': args.username,
        'password': args.password,
        'workers': args.workers,
        'depth': args.depth,
        'aggressive': args.aggressive,
        'confirm_only': args.confirm_only,
        'timeout': args.timeout,
        'ai': args.ai,
        'ai_model': args.ai_model,
        'ai_api_key': args.ai_api_key,
        'ai_concurrency': args.ai_concurrency,
        'ai_max_findings': args.ai_max_findings,
        'ai_max_output_tokens': args.ai_max_output_tokens,
        'ai_skip_overviews': args.ai_skip_overviews,
        'report_dir': args.report_dir,
    }


def main(argv: Sequence[str] | None = None) -> None:
    load_local_env()
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.gui or not argv:
        from .gui import launch_gui

        launch_gui()
        return

    if args.worker:
        from .worker import run_worker

        try:
            run_worker(
                rabbitmq_url=args.rabbitmq_url,
                queue_name=args.queue_name,
                default_report_dir=args.report_dir,
                prefetch=max(1, args.prefetch),
            )
        except QueueingError as exc:
            raise SystemExit(str(exc)) from exc
        return

    if not args.base_url:
        parser.error('--base-url is required unless --gui or --worker is used')
    if args.mode != 'ctf':
        raise SystemExit('Only --mode ctf is supported in this build.')

    options = scan_options_from_args(args)
    if args.queue_job:
        options.pop('ai_api_key', None)
        try:
            job_id = publish_scan_job(
                options,
                rabbitmq_url=args.rabbitmq_url,
                queue_name=args.queue_name,
            )
        except QueueingError as exc:
            raise SystemExit(str(exc)) from exc
        print(f'[+] Queued scan job {job_id} on {args.queue_name}')
        return

    from .scanner import Scanner

    Scanner(**options).run()
