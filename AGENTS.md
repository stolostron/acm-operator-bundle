# acm-operator-bundle — Agent Instructions

This repository holds manifests and build logic for the ACM operator bundle.

## What this repository contains

The ACM operator bundle packages the multiclusterhub-operator for distribution via OLM (Operator Lifecycle Manager). It includes:

- ClusterServiceVersion (CSV) manifest
- CRD manifests for MultiClusterHub
- Operator metadata and annotations
- Bundle Dockerfile and build scripts

## Repository layout

- `bundle/` - OLM bundle manifests (CSV, CRDs, metadata)
- `bundle.Dockerfile` - Dockerfile for building bundle image
- `scripts/` - Build and validation scripts
- `config/` - Kustomize overlays for bundle generation

## Build process

### Generate bundle

```bash
make bundle       # Generate bundle manifests from upstream operator
make bundle-build # Build bundle image
make bundle-push  # Push bundle image to registry
```

### Validate bundle

```bash
operator-sdk bundle validate ./bundle
```

## Dependencies

- **multiclusterhub-operator** - Upstream operator source
- **Operator SDK** - Bundle generation and validation
- **OLM** - Operator Lifecycle Manager (target platform)

## Documentation

- [OLM Bundle Format](https://olm.operatorframework.io/docs/tasks/creating-operator-bundle/)
- [ACM Operator Documentation](https://access.redhat.com/documentation/en-us/red_hat_advanced_cluster_management_for_kubernetes/)
- [Bundle Validation](https://sdk.operatorframework.io/docs/olm-integration/tutorial-bundle/)

## Common tasks

### Update bundle from upstream

```bash
# Update CSV and CRDs from multiclusterhub-operator
make bundle

# Review changes
git diff bundle/
```

### Test bundle locally

```bash
# Build and push bundle
export QUAY_USER=<your-quay-username>
make bundle-build bundle-push

# Install via OLM
operator-sdk run bundle quay.io/$QUAY_USER/acm-operator-bundle:latest
```

### Validate bundle before release

```bash
operator-sdk bundle validate ./bundle --select-optional suite=operatorframework
```
