# Contributing

Thanks for your interest in this project. A quick heads-up first: this is a personal-use tool (see [README.md](README.md)), maintained by one person in their spare time. Contributions are welcome, but please read the notes below so expectations are clear on both sides.

## Before you start

- This project is maintained on a best-effort basis — response times to Issues and pull requests may vary, and not every suggestion will be accepted. That's not a reflection on the idea, just a reality of a solo-maintained hobby project.
- For anything beyond a small fix, it's worth opening an Issue first to discuss the approach before investing time in a pull request.
- **Security vulnerabilities should not be reported as public Issues.** Please follow the process in [SECURITY.md](SECURITY.md) instead.

## Reporting bugs / requesting features

Please use the Issue templates under `.github/ISSUE_TEMPLATE/`. Include enough detail to reproduce the problem (steps, expected vs. actual behavior, relevant logs with any secrets/credentials redacted).

## Submitting a pull request

1. Fork the repository and create a branch from `master` for your change.
2. Keep the change focused — one logical change per pull request is easier to review than a large bundle of unrelated fixes.
3. Follow the existing code style and structure in the file(s) you're touching rather than introducing a new convention.
4. If you're changing backend (Java/Spring Boot) behavior, run the relevant tests locally before opening the PR. See the "Running Tests" section of [README.md](README.md) for how to set up the dedicated test database.
5. Describe *why* the change is needed in the PR description, not just what it does.
6. Never include real credentials, API keys, or tokens in commits, code, or PR descriptions — this is a public repository.

## What kinds of contributions are useful

- Bug fixes, especially anything affecting correctness of the vulnerability lookup results.
- Documentation fixes/clarifications (README, SECURITY.md, this file).
- Small, well-scoped improvements that don't require a broader design discussion first.

Larger architectural changes are possible but are more likely to need discussion in an Issue first, given this is a one-maintainer project.

## License

By contributing, you agree that your contributions will be licensed under the same [MIT License](LICENSE) that covers the rest of this project.
