# Include the library makefile
include $(addprefix ./vendor/github.com/openshift/build-machinery-go/make/, \
	golang.mk \
	targets/openshift/images.mk \
	targets/openshift/deps.mk \
)

GO_BUILD_PACKAGES = ./cmd/...

IMAGE_REGISTRY := registry.svc.ci.openshift.org

# This will generate target "image-ebpf-networkpolicy-controller" and make it a prerequisite to target "images".
$(call build-image,ebpf-networkpolicy-controller,ebpf-networkpolicy-controller,./Dockerfile,.)

# This builds a debug image without depending on OCP build tools...
debug-image:
	podman build --no-cache -f Dockerfile -t "ebpf-networkpolicy:debug" .
