FROM fedora:36 AS builder

RUN INSTALL_PKGS=" \
      golang git \
      " && \
    dnf install -y --setopt=tsflags=nodocs --setopt=skip_missing_names_on_install=False $INSTALL_PKGS && \
    dnf clean all && rm -rf /var/cache/*

WORKDIR /go/src/github.com/ebpf-networking/ebpf-networkpolicy
COPY . .
RUN make build

FROM fedora:36
COPY --from=builder /go/src/github.com/ebpf-networking/ebpf-networkpolicy/ebpf-networkpolicy-controller /usr/bin
