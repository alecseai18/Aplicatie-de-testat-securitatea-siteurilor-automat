from __future__ import annotations

import dataclasses
import os
import queue
import threading
import time
from urllib.parse import urlparse

from .desktop import open_path
from .env import get_gemini_api_key, load_local_env
from .scanner import Scanner

def launch_gui():
    load_local_env()
    try:
        import tkinter as tk
        from tkinter import messagebox, ttk
    except Exception as e:
        raise SystemExit(f'Tkinter GUI is not available in this Python installation: {e}')

    class ScannerGUI:
        def __init__(self, root):
            self.root = root
            self.root.title('CTF Aggressive Scanner')
            self.root.geometry('1180x760')
            self.root.minsize(760, 500)
            self.events = queue.Queue()
            self.scan_thread = None
            self.scanner = None
            self.stop_event = threading.Event()
            self.running = False
            self.report_dir = os.path.abspath('reports')

            self.base_url_var = tk.StringVar(value='http://127.0.0.1:5000')
            self.username_var = tk.StringVar(value='admin')
            self.password_var = tk.StringVar(value='admin123')
            self.workers_var = tk.IntVar(value=80)
            self.depth_var = tk.IntVar(value=4)
            self.timeout_var = tk.DoubleVar(value=4.0)
            self.aggressive_var = tk.BooleanVar(value=True)
            self.confirm_only_var = tk.BooleanVar(value=False)
            self.ai_var = tk.BooleanVar(value=False)
            self.ai_model_var = tk.StringVar(value='gemini-3-flash-preview')
            self.ai_key_var = tk.StringVar(value=get_gemini_api_key())
            self.ai_concurrency_var = tk.IntVar(value=4)
            self.ai_max_findings_var = tk.IntVar(value=8)
            self.ai_max_output_tokens_var = tk.IntVar(value=2048)
            self.ai_skip_overviews_var = tk.BooleanVar(value=False)
            self.status_var = tk.StringVar(value='Ready')
            self.subtitle_var = tk.StringVar(value='Local / CTF vulnerability scanner')
            self.urls_var = tk.StringVar(value='0')
            self.forms_var = tk.StringVar(value='0')
            self.findings_var = tk.StringVar(value='0')
            self.finding_rows = {}
            self._sidebar_canvas = None

            self._style()
            self._build()
            self.root.after(100, self._drain_events)

        def _style(self):
            style = ttk.Style(self.root)
            try:
                style.theme_use('clam')
            except tk.TclError:
                pass
            self.bg = '#101317'
            self.panel = '#171d24'
            self.panel_alt = '#222b35'
            self.field = '#0c1016'
            self.text = '#f2f5f8'
            self.muted = '#aab4c0'
            self.accent = '#2dd4bf'
            self.accent_alt = '#60a5fa'
            self.danger = '#f87171'
            self.root.configure(bg=self.bg)
            style.configure('.', background=self.bg, foreground=self.text, fieldbackground=self.field, bordercolor=self.panel_alt, lightcolor=self.panel_alt, darkcolor=self.panel_alt)
            style.configure('TFrame', background=self.bg)
            style.configure('Panel.TFrame', background=self.panel)
            style.configure('TLabel', background=self.bg, foreground=self.text)
            style.configure('Muted.TLabel', background=self.bg, foreground=self.muted)
            style.configure('Panel.TLabel', background=self.panel, foreground=self.text)
            style.configure('Title.TLabel', background=self.bg, foreground=self.text, font=('Segoe UI', 20, 'bold'))
            style.configure('Subtitle.TLabel', background=self.bg, foreground=self.muted, font=('Segoe UI', 9))
            style.configure('Section.TLabel', background=self.bg, foreground=self.text, font=('Segoe UI', 10, 'bold'))
            style.configure('Metric.TLabel', background=self.panel, foreground=self.accent, font=('Segoe UI', 18, 'bold'))
            style.configure('MetricName.TLabel', background=self.panel, foreground=self.muted, font=('Segoe UI', 8, 'bold'))
            style.configure('Status.TLabel', background=self.panel_alt, foreground=self.accent, font=('Segoe UI', 9, 'bold'), padding=(10, 5))
            style.configure('TLabelframe', background=self.bg, foreground=self.text, bordercolor=self.panel_alt)
            style.configure('TLabelframe.Label', background=self.bg, foreground=self.text, font=('Segoe UI', 10, 'bold'))
            style.configure('TEntry', fieldbackground=self.field, foreground=self.text, insertcolor=self.text, padding=(8, 5))
            style.configure('TSpinbox', fieldbackground=self.field, foreground=self.text, arrowsize=13, padding=(8, 5))
            style.configure('TButton', background=self.panel_alt, foreground=self.text, borderwidth=0, focusthickness=0, padding=(12, 8), font=('Segoe UI', 9, 'bold'))
            style.map('TButton', background=[('active', '#2f3a46')])
            style.configure('Accent.TButton', background=self.accent, foreground='#061310')
            style.map('Accent.TButton', background=[('active', '#5eead4')])
            style.configure('Danger.TButton', background='#7f1d1d', foreground='#fee2e2')
            style.map('Danger.TButton', background=[('active', '#991b1b')])
            style.configure('TCheckbutton', background=self.bg, foreground=self.text, padding=(0, 3))
            style.configure('TNotebook', background=self.bg, borderwidth=0)
            style.configure('TNotebook.Tab', background=self.panel, foreground=self.muted, padding=(16, 9), font=('Segoe UI', 9, 'bold'))
            style.map('TNotebook.Tab', background=[('selected', self.panel_alt)], foreground=[('selected', self.text)])
            style.configure('Treeview', background=self.field, fieldbackground=self.field, foreground=self.text, rowheight=30, borderwidth=0, font=('Segoe UI', 9))
            style.configure('Treeview.Heading', background=self.panel_alt, foreground=self.text, font=('Segoe UI', 9, 'bold'))
            style.map('Treeview', background=[('selected', '#115e59')])
            style.configure('Horizontal.TProgressbar', background=self.accent, troughcolor=self.panel, thickness=8)

        def _build(self):
            outer = ttk.Frame(self.root, padding=(18, 14, 18, 16))
            outer.pack(fill='both', expand=True)
            outer.columnconfigure(0, weight=1)
            outer.rowconfigure(2, weight=1)

            header = ttk.Frame(outer)
            header.grid(row=0, column=0, sticky='ew')
            header.columnconfigure(0, weight=1)
            title_box = ttk.Frame(header)
            title_box.grid(row=0, column=0, sticky='w')
            ttk.Label(title_box, text='CTF Aggressive Scanner', style='Title.TLabel').pack(anchor='w')
            ttk.Label(title_box, textvariable=self.subtitle_var, style='Subtitle.TLabel').pack(anchor='w', pady=(2, 0))
            ttk.Label(header, textvariable=self.status_var, style='Status.TLabel').grid(row=0, column=1, sticky='e')

            self.progress = ttk.Progressbar(outer, mode='determinate', maximum=13)
            self.progress.grid(row=1, column=0, sticky='ew', pady=(14, 14))

            body = ttk.Panedwindow(outer, orient='horizontal')
            body.grid(row=2, column=0, sticky='nsew')

            controls = ttk.Frame(body, width=320)
            controls.pack_propagate(False)
            body.add(controls, weight=0)

            right = ttk.Frame(body)
            right.rowconfigure(1, weight=1)
            right.columnconfigure(0, weight=1)
            body.add(right, weight=1)

            actions = ttk.Frame(controls, style='Panel.TFrame', padding=12)
            actions.pack(fill='x', pady=(0, 12))
            self.start_btn = ttk.Button(actions, text='Start scan', style='Accent.TButton', command=self._start_scan)
            self.start_btn.grid(row=0, column=0, sticky='ew', padx=(0, 6), pady=(0, 8))
            self.stop_btn = ttk.Button(actions, text='Stop', style='Danger.TButton', command=self._stop_scan, state='disabled')
            self.stop_btn.grid(row=0, column=1, sticky='ew', padx=(6, 0), pady=(0, 8))
            ttk.Button(actions, text='Open report', command=self._open_report).grid(row=1, column=0, sticky='ew', padx=(0, 6))
            ttk.Button(actions, text='Reports folder', command=self._open_reports_folder).grid(row=1, column=1, sticky='ew', padx=(6, 0))
            ttk.Button(actions, text='Open AI report', command=self._open_ai_report).grid(row=2, column=0, columnspan=2, sticky='ew', pady=(8, 0))
            actions.columnconfigure(0, weight=1)
            actions.columnconfigure(1, weight=1)

            scroll_shell, settings = self._scrollable_container(controls)
            scroll_shell.pack(fill='both', expand=True)

            ttk.Label(settings, text='Target', style='Section.TLabel').pack(anchor='w', pady=(0, 6))
            target = ttk.Frame(settings)
            target.pack(fill='x', pady=(0, 14))
            self._field(target, 'Base URL', self.base_url_var)
            self._field(target, 'Username', self.username_var)
            self._field(target, 'Password', self.password_var, show='*')

            ttk.Label(settings, text='Scan tuning', style='Section.TLabel').pack(anchor='w', pady=(2, 6))
            tuning = ttk.Frame(settings)
            tuning.pack(fill='x', pady=(0, 14))
            tuning.columnconfigure(0, weight=1)
            tuning.columnconfigure(1, weight=1)
            tuning.columnconfigure(2, weight=1)
            self._spin(tuning, 'Workers', self.workers_var, 1, 240, grid=(0, 0), padx=(0, 6))
            self._spin(tuning, 'Depth', self.depth_var, 0, 10, grid=(0, 1), padx=6)
            self._spin(tuning, 'Timeout', self.timeout_var, 0.5, 30.0, increment=0.5, grid=(0, 2), padx=(6, 0))
            ttk.Checkbutton(tuning, text='Aggressive payload set', variable=self.aggressive_var).grid(row=1, column=0, columnspan=3, sticky='w', pady=(10, 0))
            ttk.Checkbutton(tuning, text='Confirmed findings only', variable=self.confirm_only_var).grid(row=2, column=0, columnspan=3, sticky='w', pady=(2, 0))

            ttk.Label(settings, text='AI reports', style='Section.TLabel').pack(anchor='w', pady=(2, 6))
            ai = ttk.Frame(settings)
            ai.pack(fill='x', pady=(0, 10))
            ttk.Checkbutton(ai, text='Generate AI remediation report', variable=self.ai_var).pack(anchor='w')
            self._field(ai, 'Model', self.ai_model_var)
            self._field(ai, 'Gemini API key', self.ai_key_var, show='*')
            ai_speed = ttk.Frame(ai)
            ai_speed.pack(fill='x', pady=(8, 0))
            ai_speed.columnconfigure(0, weight=1)
            ai_speed.columnconfigure(1, weight=1)
            self._spin(ai_speed, 'Parallel calls', self.ai_concurrency_var, 1, 8, grid=(0, 0), padx=(0, 6))
            self._spin(ai_speed, 'Max findings', self.ai_max_findings_var, 0, 100, grid=(0, 1), padx=(6, 0))
            self._spin(ai, 'Max output tokens', self.ai_max_output_tokens_var, 512, 8192, increment=256)
            ttk.Checkbutton(ai, text='Skip executive/checklist AI calls', variable=self.ai_skip_overviews_var).pack(anchor='w', pady=(6, 0))

            metrics = ttk.Frame(right, style='Panel.TFrame', padding=12)
            metrics.grid(row=0, column=0, sticky='ew', pady=(0, 12), padx=(12, 0))
            metrics.columnconfigure(0, weight=1)
            metrics.columnconfigure(1, weight=1)
            metrics.columnconfigure(2, weight=1)
            self._metric(metrics, 'URLs', self.urls_var).grid(row=0, column=0, sticky='ew')
            self._metric(metrics, 'Forms', self.forms_var).grid(row=0, column=1, sticky='ew', padx=10)
            self._metric(metrics, 'Findings', self.findings_var).grid(row=0, column=2, sticky='ew')

            tabs = ttk.Notebook(right)
            tabs.grid(row=1, column=0, sticky='nsew', padx=(12, 0))
            tabs.add(self._findings_tab(tabs), text='Findings')
            tabs.add(self._log_tab(tabs), text='Live log')
            tabs.add(self._report_tab(tabs), text='Report preview')

        def _scrollable_container(self, parent):
            shell = ttk.Frame(parent)
            canvas = tk.Canvas(shell, bg=self.bg, highlightthickness=0, bd=0)
            scrollbar = ttk.Scrollbar(shell, orient='vertical', command=canvas.yview)
            content = ttk.Frame(canvas)
            window_id = canvas.create_window((0, 0), window=content, anchor='nw')
            self._sidebar_canvas = canvas

            def sync_scrollregion(event=None):
                canvas.configure(scrollregion=canvas.bbox('all'))

            def sync_width(event):
                canvas.itemconfigure(window_id, width=event.width)

            def wheel(event):
                canvas.yview_scroll(int(-1 * (event.delta / 120)), 'units')

            content.bind('<Configure>', sync_scrollregion)
            canvas.bind('<Configure>', sync_width)
            canvas.bind('<Enter>', lambda event: canvas.bind_all('<MouseWheel>', wheel))
            canvas.bind('<Leave>', lambda event: canvas.unbind_all('<MouseWheel>'))
            canvas.configure(yscrollcommand=scrollbar.set)
            canvas.pack(side='left', fill='both', expand=True)
            scrollbar.pack(side='right', fill='y')
            return shell, content

        def _field(self, parent, label, variable, show=None):
            frame = ttk.Frame(parent)
            frame.pack(fill='x', pady=(7, 0))
            ttk.Label(frame, text=label).pack(anchor='w')
            entry = ttk.Entry(frame, textvariable=variable, show=show)
            entry.pack(fill='x', pady=(4, 0))
            return entry

        def _spin(self, parent, label, variable, start, end, increment=1, grid=None, padx=0):
            frame = ttk.Frame(parent)
            if grid:
                row, column = grid
                frame.grid(row=row, column=column, sticky='ew', padx=padx)
            else:
                frame.pack(fill='x', pady=(8, 0))
            ttk.Label(frame, text=label).pack(anchor='w')
            spin = ttk.Spinbox(frame, textvariable=variable, from_=start, to=end, increment=increment)
            spin.pack(fill='x', pady=(4, 0))
            return spin

        def _metric(self, parent, label, variable):
            box = ttk.Frame(parent, style='Panel.TFrame')
            ttk.Label(box, textvariable=variable, style='Metric.TLabel').pack()
            ttk.Label(box, text=label, style='Panel.TLabel').pack()
            return box

        def _findings_tab(self, parent):
            frame = ttk.Frame(parent, padding=10)
            frame.rowconfigure(0, weight=1)
            frame.rowconfigure(2, weight=0)
            frame.columnconfigure(0, weight=1)
            columns = ('severity', 'status', 'name', 'url')
            self.findings_tree = ttk.Treeview(frame, columns=columns, show='headings')
            widths = {'severity': 90, 'status': 100, 'name': 320, 'url': 520}
            for col in columns:
                self.findings_tree.heading(col, text=col.title())
                self.findings_tree.column(col, width=widths[col], anchor='w', stretch=True)
            yscroll = ttk.Scrollbar(frame, orient='vertical', command=self.findings_tree.yview)
            self.findings_tree.configure(yscrollcommand=yscroll.set)
            self.findings_tree.grid(row=0, column=0, sticky='nsew')
            yscroll.grid(row=0, column=1, sticky='ns')
            self.findings_tree.bind('<Configure>', self._resize_finding_columns)
            ttk.Label(frame, text='Evidence and recommendation', style='Muted.TLabel').grid(row=1, column=0, sticky='w', pady=(10, 4))
            self.finding_detail_text = tk.Text(frame, height=6, bg=self.field, fg=self.text, insertbackground=self.text, relief='flat', wrap='word', padx=10, pady=8)
            self.finding_detail_text.grid(row=2, column=0, columnspan=2, sticky='ew')
            self.findings_tree.bind('<<TreeviewSelect>>', self._show_finding_detail)
            self.findings_tree.tag_configure('critical', foreground='#fca5a5')
            self.findings_tree.tag_configure('high', foreground='#fdba74')
            self.findings_tree.tag_configure('medium', foreground='#fde68a')
            self.findings_tree.tag_configure('low', foreground='#a7f3d0')
            self.findings_tree.tag_configure('info', foreground='#bfdbfe')
            return frame

        def _resize_finding_columns(self, event=None):
            width = max(self.findings_tree.winfo_width() - 28, 320)
            fixed = 185
            remaining = max(width - fixed, 160)
            name_width = max(180, int(remaining * 0.42))
            url_width = max(220, remaining - name_width)
            self.findings_tree.column('severity', width=85, stretch=False)
            self.findings_tree.column('status', width=100, stretch=False)
            self.findings_tree.column('name', width=name_width, stretch=True)
            self.findings_tree.column('url', width=url_width, stretch=True)

        def _log_tab(self, parent):
            frame = ttk.Frame(parent, padding=10)
            frame.rowconfigure(0, weight=1)
            frame.columnconfigure(0, weight=1)
            self.log_text = tk.Text(frame, bg='#020617', fg=self.text, insertbackground=self.text, relief='flat', wrap='word', padx=12, pady=12)
            scroll = ttk.Scrollbar(frame, orient='vertical', command=self.log_text.yview)
            self.log_text.configure(yscrollcommand=scroll.set)
            self.log_text.grid(row=0, column=0, sticky='nsew')
            scroll.grid(row=0, column=1, sticky='ns')
            return frame

        def _report_tab(self, parent):
            frame = ttk.Frame(parent, padding=10)
            frame.rowconfigure(0, weight=1)
            frame.columnconfigure(0, weight=1)
            self.report_text = tk.Text(frame, bg='#020617', fg=self.text, insertbackground=self.text, relief='flat', wrap='word', padx=12, pady=12)
            scroll = ttk.Scrollbar(frame, orient='vertical', command=self.report_text.yview)
            self.report_text.configure(yscrollcommand=scroll.set)
            self.report_text.grid(row=0, column=0, sticky='nsew')
            scroll.grid(row=0, column=1, sticky='ns')
            return frame

        def _start_scan(self):
            if self.running:
                return
            base_url = self.base_url_var.get().strip()
            if not base_url:
                messagebox.showerror('Missing target', 'Base URL is required.')
                return
            parsed = urlparse(base_url)
            if parsed.scheme not in ('http', 'https') or not parsed.netloc:
                messagebox.showerror('Invalid target', 'Base URL must look like http://127.0.0.1:5000')
                return
            try:
                workers = int(self.workers_var.get())
                depth = int(self.depth_var.get())
                timeout = float(self.timeout_var.get())
                ai_concurrency = int(self.ai_concurrency_var.get())
                ai_max_findings = int(self.ai_max_findings_var.get())
                ai_max_output_tokens = int(self.ai_max_output_tokens_var.get())
            except (ValueError, tk.TclError):
                messagebox.showerror('Invalid scan tuning', 'Workers, Depth, Timeout, and AI speed settings must be valid numbers.')
                return
            if workers < 1 or depth < 0 or timeout <= 0:
                messagebox.showerror('Invalid scan tuning', 'Workers must be >= 1, Depth >= 0, and Timeout > 0.')
                return
            if ai_concurrency < 1 or ai_concurrency > 8 or ai_max_findings < 0 or ai_max_output_tokens < 512:
                messagebox.showerror('Invalid AI tuning', 'Parallel calls must be 1-8, Max findings must be >= 0, and Max output tokens must be >= 512.')
                return
            ai_key = self.ai_key_var.get().strip()
            if bool(self.ai_var.get()) and not get_gemini_api_key(ai_key):
                messagebox.showerror('Missing AI key', 'Set a Gemini API key in the AI section or in GEMINI_API_KEY before enabling AI reports.')
                return
            self.running = True
            self.stop_event = threading.Event()
            self.start_btn.configure(state='disabled')
            self.stop_btn.configure(state='normal')
            self.status_var.set('Starting scan')
            self.subtitle_var.set(f'{base_url} | workers={workers} | depth={depth}')
            self.progress.configure(value=0)
            self.urls_var.set('0')
            self.forms_var.set('0')
            self.findings_var.set('0')
            self.finding_rows.clear()
            self.findings_tree.delete(*self.findings_tree.get_children())
            self.finding_detail_text.delete('1.0', 'end')
            self.log_text.delete('1.0', 'end')
            self.report_text.delete('1.0', 'end')

            def run_scan():
                try:
                    scanner = Scanner(
                        base_url=base_url,
                        username=self.username_var.get().strip(),
                        password=self.password_var.get(),
                        workers=workers,
                        depth=depth,
                        aggressive=bool(self.aggressive_var.get()),
                        confirm_only=bool(self.confirm_only_var.get()),
                        timeout=timeout,
                        ai=bool(self.ai_var.get()),
                        ai_model=self.ai_model_var.get().strip(),
                        ai_api_key=ai_key,
                        ai_concurrency=ai_concurrency,
                        ai_max_findings=ai_max_findings,
                        ai_max_output_tokens=ai_max_output_tokens,
                        ai_skip_overviews=bool(self.ai_skip_overviews_var.get()),
                        log_callback=lambda msg: self.events.put(('log', msg)),
                        progress_callback=lambda label, done, total: self.events.put(('progress', label, done, total)),
                        finding_callback=lambda finding: self.events.put(('finding', dataclasses.asdict(finding))),
                        stop_event=self.stop_event,
                        report_dir=self.report_dir,
                    )
                    self.scanner = scanner
                    scanner.run()
                    self.events.put(('done', None))
                except SystemExit as e:
                    self.events.put(('log', f'[!] {e}'))
                    self.events.put(('done', None))
                except Exception as e:
                    self.events.put(('log', f'[!] GUI scan error: {type(e).__name__}: {e}'))
                    self.events.put(('done', None))

            self.scan_thread = threading.Thread(target=run_scan, daemon=True)
            self.scan_thread.start()

        def _stop_scan(self):
            if self.running:
                self.stop_event.set()
                self.status_var.set('Stopping after current requests')
                self.events.put(('log', '[!] Stop requested. Waiting for in-flight requests to finish.'))

        def _drain_events(self):
            try:
                while True:
                    event = self.events.get_nowait()
                    kind = event[0]
                    if kind == 'log':
                        self._append_log(event[1])
                    elif kind == 'progress':
                        _, label, done, total = event
                        self.progress.configure(maximum=max(total, 1), value=done)
                        self.status_var.set(f'{label}: {done}/{total}')
                    elif kind == 'finding':
                        self._add_finding(event[1])
                    elif kind == 'done':
                        self._finish_scan()
            except queue.Empty:
                pass
            self.root.after(100, self._drain_events)

        def _append_log(self, message):
            stamp = time.strftime('%H:%M:%S')
            self.log_text.insert('end', f'[{stamp}] {message}\n')
            self.log_text.see('end')

        def _add_finding(self, finding):
            values = (
                finding.get('severity', ''),
                finding.get('status', ''),
                finding.get('name', ''),
                finding.get('url', ''),
            )
            severity = finding.get('severity', 'info')
            item_id = self.findings_tree.insert('', 'end', values=values, tags=(severity,))
            self.finding_rows[item_id] = finding
            self.findings_var.set(str(len(self.findings_tree.get_children())))
            if len(self.findings_tree.get_children()) == 1:
                self.findings_tree.selection_set(item_id)
                self._show_finding_detail()

        def _show_finding_detail(self, event=None):
            selected = self.findings_tree.selection()
            self.finding_detail_text.delete('1.0', 'end')
            if not selected:
                return
            finding = self.finding_rows.get(selected[0], {})
            lines = [
                f"Evidence: {finding.get('evidence', '')}",
                '',
                f"Request/Test: {finding.get('request', '')}",
                '',
                f"Recommendation: {finding.get('recommendation', '')}",
            ]
            self.finding_detail_text.insert('end', '\n'.join(lines))

        def _finish_scan(self):
            self.running = False
            self.start_btn.configure(state='normal')
            self.stop_btn.configure(state='disabled')
            if self.scanner:
                self.urls_var.set(str(len(self.scanner.visited)))
                self.forms_var.set(str(len(self.scanner.forms)))
                self.findings_var.set(str(len(self.scanner.findings)))
            self.progress.configure(value=self.progress.cget('maximum'))
            self.status_var.set(f'Finished - {self.findings_var.get()} findings')
            self._load_report()

        def _load_report(self):
            path = os.path.join(self.report_dir, 'report.md')
            self.report_text.delete('1.0', 'end')
            if not os.path.exists(path):
                self.report_text.insert('end', 'Report not generated yet.')
                return
            with open(path, 'r', encoding='utf-8') as f:
                self.report_text.insert('end', f.read())
            ai_path = os.path.join(self.report_dir, 'ai_report.md')
            if bool(self.ai_var.get()) and os.path.exists(ai_path):
                with open(ai_path, 'r', encoding='utf-8') as f:
                    self.report_text.insert('end', '\n\n---\n\n' + f.read())

        def _open_report(self):
            path = os.path.join(self.report_dir, 'report.md')
            if not os.path.exists(path):
                messagebox.showinfo('Report', 'No report has been generated yet.')
                return
            self._open_path_or_show_error(path)

        def _open_ai_report(self):
            path = os.path.join(self.report_dir, 'ai_report.md')
            if not os.path.exists(path):
                messagebox.showinfo('AI report', 'No AI report has been generated yet. Enable AI reports and run a scan first.')
                return
            self._open_path_or_show_error(path)

        def _open_reports_folder(self):
            os.makedirs(self.report_dir, exist_ok=True)
            self._open_path_or_show_error(self.report_dir)

        def _open_path_or_show_error(self, path):
            try:
                open_path(path)
            except Exception as e:
                messagebox.showerror('Open failed', f'Could not open:\n{path}\n\n{e}')

    root = tk.Tk()
    ScannerGUI(root)
    root.mainloop()

