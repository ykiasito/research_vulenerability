# Security Policy

## About this project

This is a CSV-upload-based vulnerability pre-screening web app, designed with a GUI for non-engineers and **built for personal, individual use**. See [README.md](README.md) for details on the project's scope and intended deployment.

This GitHub repository is currently public, but the application itself is not intended to be exposed to the public internet. If you find a security issue, please report it responsibly using the process below regardless of how you came across it.

## Supported versions

This is a small personal tool without a formal release/versioning scheme. Only the latest state of the `master` branch is supported. Security fixes are not backported to older commits or branches.

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub Issues.** Issues are publicly visible, and publishing details of an unpatched vulnerability there could put users at risk before a fix is available.

Instead, please report vulnerabilities privately using GitHub's Security Advisories feature:

1. Go to the [Security tab](../../security) of this repository.
2. Click **"Report a vulnerability"**.
3. Fill in as much detail as you can, including:
   - A description of the issue and its potential impact.
   - Steps to reproduce it (proof-of-concept code or a CSV sample is helpful, if applicable).
   - The affected component (e.g., the Spring Boot backend, the Python/FastAPI LLM microservice, Docker Compose configuration, etc.).

We will make every effort to respond and address confirmed issues as promptly as possible. Response times may vary since this project is maintained on a best-effort basis, but we aim to acknowledge reports promptly and keep reporters updated on progress.

## Disclosure

Once a reported vulnerability is confirmed and a fix is available, we will coordinate with the reporter on disclosure timing before any public details are shared. We appreciate reports made in good faith and will credit reporters who wish to be acknowledged, unless they prefer to remain anonymous.
