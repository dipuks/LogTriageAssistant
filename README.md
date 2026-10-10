# LogTriage Assistant

A .NET 10 ASP.NET Core app for triaging runtime logs, application failures, dependency timeouts, and deployment issues.

## Features

- Paste log text directly into the browser UI
- Upload a log file from disk
- Detect likely failure categories and root-cause areas
- Preserve generic error and warning lines as actionable findings when no specific category matches
- Weigh multiple matching log signatures and flag performance, cache, and serialization issues
- Cap displayed findings at 500 per analysis while calculating overall severity across the full log
- Produce a summary with confidence score and severity
- Suggest actions to investigate next
- Save recent analyses to a local SQLite database
- Reopen full saved results from the recent analyses list
- Delete saved analyses from history
- Search saved analyses by file name, summary, or finding and filter by severity
- Run analyzer unit and API integration tests with `dotnet test`
- Accept log text and file uploads up to 2 MB
- Run in Docker, with a GitHub Actions build check

## Run locally

```powershell
cd C:\Projects\LogTriageAssistant
dotnet restore
dotnet run
```

Open the local address printed by `dotnet run` in a browser. The SQLite database is created automatically at `App_Data\logtriage.db`.

Run the analyzer unit and API integration tests from the repository root with:

```powershell
dotnet test
```

To store the database elsewhere, set the `Storage__DatabasePath` environment variable before starting the app.

## Run with Docker

```powershell
docker build -t logtriage .
docker run --rm -p 127.0.0.1:8080:8080 -v logtriage-data:/app/App_Data logtriage
```

Open `http://localhost:8080`. The named Docker volume keeps the SQLite database when the container is replaced.

## Example API

### Analyze raw log text

```http
POST /api/analyze
Content-Type: application/json

{
  "logText": "2026-10-06 12:18:01 ERROR Failed to connect to database",
  "fileName": "sample.log"
}
```

### Upload a file

```powershell
curl.exe -F "file=@sample.log" http://localhost:8080/api/analyze-file
```

The upload field must be named `file`. `/api/recent?limit=10` returns the newest saved analyses; the limit is clamped to 1-100. `/health` reports application health.

## Current limitations

- Analysis uses local, explainable keyword rules; it does not send logs to an AI service.
- SQLite is intended for local/single-instance use. Multi-instance deployments need shared durable storage.
- The app does not include authentication. Keep it on a trusted machine/network and do not expose it directly to the public internet.
- Full uploaded log files are not stored. Saved analysis results include matched log-line excerpts, clipped to 220 characters, so avoid submitting secrets or sensitive production data.
