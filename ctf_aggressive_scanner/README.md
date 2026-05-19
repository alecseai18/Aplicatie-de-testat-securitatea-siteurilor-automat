# CTF Aggressive Scanner

Scanner web local/CTF pentru vulnerabilitati, cu GUI desktop, rapoarte Markdown/JSON si suport optional pentru joburi RabbitMQ.

## Ce s-a modularizat

Codul nu mai sta intr-un singur `main.py`. Intrarea principala este subtire, iar functionalitatea este impartita asa:

- `main.py` - entrypoint compatibil.
- `ctf_aggressive_scanner/cli.py` - argumente CLI, rulare locala, worker si publicare joburi.
- `ctf_aggressive_scanner/scanner.py` - engine-ul de scanare, threading, HTTP sessions si teste.
- `ctf_aggressive_scanner/models.py` - dataclass-uri pentru formulare si finding-uri.
- `ctf_aggressive_scanner/payloads.py` - payload-uri si constante de test.
- `ctf_aggressive_scanner/gui.py` - interfata Tkinter.
- `ctf_aggressive_scanner/queueing.py` - publicare/consum RabbitMQ cu coada durabila si ACK manual.
- `ctf_aggressive_scanner/worker.py` - worker pentru procesarea scanarilor din coada.

## Notiuni aplicate din cursuri

- Docker: `Dockerfile`, `.dockerignore`, `docker-compose.yml`, container reproducibil si volum pentru rapoarte.
- RabbitMQ: producer/consumer, coada durabila, mesaje persistente, `prefetch` pentru load balancing si ACK manual.
- Multithreading: pool-uri de threaduri pentru cereri I/O, sesiuni HTTP per thread, stop event si limite de worker.
- Django/HTTP/security: verificari pentru headers, CSRF, CORS-like trust boundaries, status codes, request/response si expuneri sensibile.
- ML/AI: generare optionala de rapoarte defensive prin Gemini, doar pentru remediere si prioritizare.

## Instalare locala

```bash
pip install -r requirements.txt
```

## Rulare fara AI

```bash
python main.py --base-url http://127.0.0.1:5000 --username admin --password admin123 --mode ctf --aggressive --workers 80 --depth 4
```

## GUI desktop

```bash
python main.py
```

sau:

```bash
python main.py --gui
```

In WSL, butoanele `Open report`, `Open AI report` si `Reports folder` incearca, in ordine, `wslview`, `explorer.exe` sau `xdg-open`. Daca vrei deschidere directa in Windows, instaleaza utilitarul WSL:

```bash
sudo apt install -y wslu
```

## Rapoarte

Implicit, rapoartele sunt scrise in `reports/`:

- `reports/report.md`
- `reports/report.json`

Poti schimba directorul:

```bash
python main.py --base-url http://127.0.0.1:5000 --report-dir reports/lab-1
```

## Docker

Build:

```bash
docker build -t ctf-aggressive-scanner .
```

Rulare directa:

```bash
docker run --rm -v "${PWD}/reports:/app/reports" ctf-aggressive-scanner python main.py --base-url http://host.docker.internal:5000 --aggressive --workers 80
```

Pe CMD clasic, inlocuieste `"${PWD}/reports"` cu `"%cd%/reports"`.

## RabbitMQ worker

Porneste brokerul si workerul:

```bash
docker compose up --build rabbitmq scanner-worker
```

RabbitMQ Management UI:

- URL: http://localhost:15672
- user/parola: `guest` / `guest`

Trimite o scanare in coada:

```bash
python main.py --queue-job --base-url http://host.docker.internal:5000 --aggressive --workers 80 --rabbitmq-url amqp://guest:guest@localhost:5672/%2F
```

Workerul va scrie rapoartele in `reports/<job_id>/`.

## AI/Gemini

Aplicatia incarca automat cheia Gemini din `.env.local`, `.env`, `GEMINI_API_KEY` sau `GOOGLE_API_KEY`.
Pentru acest proiect, cheia locala este deja salvata in `.env.local` ca `GEMINI_API_KEY`.

Fisierul `.env.local` este ignorat de Git si de build-ul Docker, ca sa nu ajunga cheia in cod sau in imagine.

Daca vrei sa setezi cheia manual in environment:

WSL/Linux:

```bash
export GEMINI_API_KEY="YOUR_GEMINI_API_KEY"
```

PowerShell:

```bash
$env:GEMINI_API_KEY="YOUR_GEMINI_API_KEY"
```

In GUI poti bifa `Generate AI remediation report` si poti introduce cheia direct in campul `Gemini API key`.

Rulare cu raport AI:

```bash
python main.py --base-url http://127.0.0.1:5000 --username admin --password admin123 --mode ctf --aggressive --workers 80 --depth 4 --ai
```

Rulare AI mai rapida:

```bash
python main.py --base-url http://127.0.0.1:5000 --username admin --password admin123 --mode ctf --aggressive --workers 80 --depth 4 --ai --ai-concurrency 4 --ai-max-findings 8 --ai-skip-overviews
```

Optiuni de viteza:

- `--ai-concurrency 4` ruleaza pana la 4 analize Gemini in paralel. Poti incerca `6` sau `8`, dar daca API-ul da rate limit, revino la `4`.
- `--ai-max-findings 8` trimite la AI doar primele 8 finding-uri dupa prioritate. `0` inseamna toate finding-urile.
- `--ai-skip-overviews` sare peste cele doua apeluri extra pentru `executive_summary.md` si `developer_checklist.md`.
- `--ai-max-output-tokens 2048` controleaza cat de lung poate fi raspunsul per apel AI; valori mai mici sunt mai rapide, dar pot taia detalii.

Sau pentru un test local rapid, fara sa setezi environment variable:

```bash
python main.py --base-url http://127.0.0.1:5000 --aggressive --ai --ai-concurrency 4 --ai-max-findings 5 --ai-skip-overviews --ai-api-key "YOUR_GEMINI_API_KEY"
```

Docker direct cu AI:

```bash
docker run --rm --env-file .env.local -v "${PWD}/reports:/app/reports" ctf-aggressive-scanner python main.py --base-url http://host.docker.internal:5000 --aggressive --workers 80 --ai --ai-concurrency 4 --ai-max-findings 8 --ai-skip-overviews
```

Workerul Docker Compose citeste `.env.local` automat prin `env_file`, deci joburile cu `--ai` vor avea cheia in container.

AI-ul nu repara automat aplicatia tinta. Dupa ce scannerul gaseste vulnerabilitati, trimite catre Gemini finding-urile detectate si genereaza recomandari concrete de remediere: cauza probabila in backend, pasi de fix, exemple sigure de implementare, checklist si teste de regresie.

Rapoarte AI:

- `reports/ai_report.md`
- `reports/executive_summary.md`
- `reports/developer_checklist.md`
- `reports/report_ai_enriched.json`

## Note de siguranta

- Scannerul refuza implicit tinte publice si este gandit pentru localhost, retele private sau CTF-uri autorizate.
- Nu hardcoda chei API. Foloseste variabile de mediu.
- Daca rulezi workerul in Docker si tinta ruleaza pe host, foloseste `host.docker.internal` in loc de `127.0.0.1`.
