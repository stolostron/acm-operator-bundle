# Contributing to acm-operator-bundle

Thank you for your interest in contributing to acm-operator-bundle!

## Getting Started

### Prerequisites

- Operator SDK 1.28+
- Podman or Docker
- Access to a Quay.io account for testing
- Basic understanding of OLM bundle format

## Development Workflow

### Building

```bash
make bundle        # Generate bundle manifests
make bundle-build  # Build bundle image
```

### Testing

```bash
# Validate bundle format
operator-sdk bundle validate ./bundle

# Full validation suite
operator-sdk bundle validate ./bundle --select-optional suite=operatorframework
```

### Code Style

- Bundle manifests follow OLM schema
- Use `make bundle` to regenerate from upstream operator
- Validate changes with `operator-sdk bundle validate`

## Pull Request Process

1. Fork the repository and create a branch from `main`
2. Make your changes
3. Run validation: `operator-sdk bundle validate ./bundle`
4. Submit a pull request with a clear description

### PR Requirements

- [ ] Bundle validates successfully
- [ ] Manifests are up-to-date with upstream operator
- [ ] Commit messages are descriptive
- [ ] Changes include rationale (manual edit vs. upstream sync)

## Reporting Issues

File issues in this repository with:
- Clear description of the problem
- Bundle version affected
- Steps to reproduce
- Expected vs actual behavior

## Communication

- **Slack Channels**:
  - `#forum-acm-hub-installer` - General discussion
  - `#team-acm-hub-installer` - Team channel
- **Jira**: [ACM Project](https://issues.redhat.com/browse/ACM) (component: Installer)

## License

See [LICENSE](LICENSE) file for license information.
