FROM scratch

COPY ./manifests /manifests
COPY ./metadata /metadata
COPY ./extras /extras

LABEL com.redhat.delivery.operator.bundle="true" \
      operators.operatorframework.io.bundle.mediatype.v1="registry+v1" \
      operators.operatorframework.io.bundle.manifests.v1="manifests/" \
      operators.operatorframework.io.bundle.metadata.v1="metadata/" \
      operators.operatorframework.io.bundle.package.v1="advanced-cluster-management" \
      operators.operatorframework.io.bundle.channels.v1="release-2.17" \
      operators.operatorframework.io.bundle.channel.default.v1="release-2.17" \
      com.redhat.openshift.versions="v4.19-v4.23"

LABEL com.redhat.component="acm-operator-bundle-container" \
      name="rhacm2/acm-operator-bundle" \
      version="2.17.0-20" \
      summary="acm-operator-bundle" \
      io.openshift.expose-services="" \
      io.openshift.tags="data,images" \
      io.k8s.display-name="acm-operator-bundle" \
      io.k8s.description="Operator bundle for Red Hat Advanced Cluster Management"  \
      maintainer="['acm-component-maintainers@redhat.com']" \
      description="acm-operator-bundle" \
      konflux.additional-tags="v2.17.0-20,snapshot-release-acm-217-20260218-181525-000-4y" \
      vendor="Red Hat, Inc." \
      url="https://github.com/stolostron/acm-operator-bundle" \
      release="2.17.0-20" \
      distribution-scope="public" \
      cpe="cpe:/a:redhat:acm:2.17::el9"
