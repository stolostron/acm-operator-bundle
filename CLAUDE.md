# CLAUDE.md

@AGENTS.md

## Build commands

```bash
make bundle        # Generate bundle manifests
make bundle-build  # Build bundle image
make bundle-push   # Push bundle image
```

## Test commands

```bash
operator-sdk bundle validate ./bundle                                  # Validate bundle
operator-sdk bundle validate ./bundle --select-optional suite=operatorframework  # Full validation
```

## Local development

### Generate bundle from upstream

```bash
# Pull latest from multiclusterhub-operator
make bundle

# Review generated manifests
ls -la bundle/manifests/
```

### Test bundle installation

```bash
# Build and push
export QUAY_USER=<your-quay-username>
make bundle-build bundle-push

# Install via OLM
operator-sdk run bundle quay.io/$QUAY_USER/acm-operator-bundle:latest

# Uninstall
operator-sdk cleanup acm-operator
```
