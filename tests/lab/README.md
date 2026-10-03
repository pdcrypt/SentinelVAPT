# Local lab target

A static site for **manual** end-to-end scans inside Docker Compose. The
automated test suites do not use it; they start their own servers on
127.0.0.1.

```powershell
docker compose --profile lab up -d
```

The worker reaches it as `http://lab-target/` on the compose network (a private
address, so the scanner's lab-only policy allows it). Its host port is bound to
`127.0.0.1:8081` only. Create a `local_lab` target with base URL
`http://lab-target/` and in-scope host `lab-target`, start an assessment, and
request a scan.

The pages contain no real data; the hidden form value is a fake used to show
that redaction works.
