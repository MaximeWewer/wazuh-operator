# Contributing Guide

Thank you for your interest in contributing to the Wazuh Operator!

## Getting Started

### Prerequisites

- Go 1.25+
- Docker
- kubectl
- A Kubernetes cluster (minikube recommended for development)
- Make

### Setting Up Development Environment

```bash
# Clone the repository
git clone https://github.com/MaximeWewer/wazuh-operator.git
cd wazuh-operator

# Install dependencies
go mod download

# Generate code and manifests
make manifests generate

# Verify build
make build

# Run tests
make test
```

### Running Locally

```bash
# Start minikube
minikube start --cpus=4 --memory=8192

# Install CRDs
make install

# Run the operator locally
make run
```

## Development Workflow

### 1. Create a Branch

```bash
git checkout -b feature/my-feature
# or
git checkout -b fix/my-bugfix
```

### 2. Make Changes

Follow the code style guidelines in [code-style.md](code-style.md).

### 3. Test Your Changes

```bash
# Run unit tests
make test

# Build and test in cluster
make docker-build IMG=wazuh-operator:dev
minikube image load wazuh-operator:dev
make deploy IMG=wazuh-operator:dev

# Test with a sample cluster
kubectl apply -f config/samples/wazuh_v1alpha1_wazuhcluster_minimal.yaml
```

### 4. Submit a Pull Request

1. Push your branch
2. Open a Pull Request against `main`
3. Fill in the PR template
4. Wait for CI checks to pass
5. Request review

## Code Organization

### Adding a New CRD

1. Define types in `api/v1alpha1/<name>_types.go`
2. Add controller in `internal/controller/<domain>/`
3. Register controller in `cmd/wazuh-operator/main.go`
4. Generate manifests: `make manifests`
5. Add sample in `config/samples/`

### Adding a New Feature to WazuhCluster

1. Add field to `WazuhClusterSpec` in `api/v1alpha1/wazuhcluster_types.go`
2. Add builder in `pkg/resources/` or update existing
3. Update reconciler in `internal/controller/wazuhcluster/`
4. Add tests
5. Update documentation

## Pull Request Guidelines

### PR Title Format

```
<type>(<scope>): <description>

Examples:
feat(cluster): add log rotation support
fix(certificates): handle renewal race condition
docs(readme): update installation instructions
refactor(indexer): simplify config builder
```

Types:

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `refactor`: Code change that neither fixes a bug nor adds a feature
- `test`: Adding missing tests
- `chore`: Maintenance tasks

### PR Checklist

- [ ] Tests pass (`make test`)
- [ ] Code builds (`make build`)
- [ ] Documentation updated
- [ ] CRD changes regenerated (`make manifests`)
- [ ] No breaking changes (or documented)

## Reporting Issues

### Bug Reports

Include:

1. Operator version
2. Kubernetes version
3. Steps to reproduce
4. Expected vs actual behavior
5. Relevant logs

### Feature Requests

Include:

1. Use case description
2. Proposed solution
3. Alternatives considered

## Code Review

All submissions require review. Reviewers will check:

- Code quality and style
- Test coverage
- Documentation
- Backwards compatibility

## Community

- GitHub Issues: Bug reports and feature requests
- Pull Requests: Code contributions
- Discussions: General questions and ideas

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
