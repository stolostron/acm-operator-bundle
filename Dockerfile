FROM scratch

COPY ./manifests /manifests
COPY ./metadata /metadata
COPY ./extras /extras

LABEL com.redhat.delivery.operator.bundle="true" \
      operators.operatorframework.io.bundle.mediatype.v1="registry+v1" \
      operators.operatorframework.io.bundle.manifests.v1="manifests/" \
      operators.operatorframework.io.bundle.metadata.v1="metadata/" \
      operators.operatorframework.io.bundle.package.v1="advanced-cluster-management" \
      operators.operatorframework.io.bundle.channels.v1="release-2.16" \
      operators.operatorframework.io.bundle.channel.default.v1="release-2.16" \
      com.redhat.openshift.versions="v4.18-v4.22"

LABEL com.redhat.component="acm-operator-bundle-container" \
      name="rhacm2/acm-operator-bundle" \
      version="2.16.0-199" \
      summary="acm-operator-bundle" \
      io.openshift.expose-services="" \
      io.openshift.tags="data,images" \
      io.k8s.display-name="acm-operator-bundle" \
      io.k8s.description="Operator bundle for Red Hat Advanced Cluster Management"  \
      maintainer="['acm-component-maintainers@redhat.com']" \
      description="acm-operator-bundle" \
      konflux.additional-tags="v2.16.0-199,snapshot-release-acm-216-20260130-082806-000" \
      vendor="Red Hat, Inc." \
      url="https://github.com/stolostron/acm-operator-bundle" \
      release="2.16.0-199" \
      distribution-scope="public" \
      cpe="cpe:/a:redhat:acm:2.16::el9"
