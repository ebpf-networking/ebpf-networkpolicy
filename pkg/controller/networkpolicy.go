package controller

import (
	"math"
	"net"
	"reflect"
	"sync"

	"golang.org/x/sys/unix"

	"k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	corev1listers "k8s.io/client-go/listers/core/v1"
	networkingv1listers "k8s.io/client-go/listers/networking/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"

	"github.com/ebpf-networking/ebpf-networkpolicy/pkg/util"
	"github.com/ebpf-networking/ebpf-networkpolicy/pkg/util/ranges"
)

type networkPolicyController struct {
	sync.Mutex

	client    kubernetes.Interface
	informers *util.InformerManager

	namespaceLister     corev1listers.NamespaceLister
	podLister           corev1listers.PodLister
	networkPolicyLister networkingv1listers.NetworkPolicyLister

	updates chan struct{}
	policies []*networkPolicy
}

// networkPolicy represents a networkingv1.NetworkPolicy with all of the
// pod/namespace labels converted to pods and named ports converted to numeric.
type networkPolicy struct {
	policy *networkingv1.NetworkPolicy

	targets []*v1.Pod

	ingress *[]*networkPolicyRule
	egress  *[]*networkPolicyRule
}

// A parsed NetworkPolicy rule. If ports is nil then it does not restrict based on port.
// If peer is nil then it does not restrict on source/destination.
type networkPolicyRule struct {
	port *networkPolicyPort
	peer *networkPolicyPeer
}

type networkPolicyPort struct {
	protocol v1.Protocol
	port     uint16
	portMask uint16
}

type networkPolicyPeer struct {
	pods  []*v1.Pod
	cidrs []string
}

func newNetworkPolicyController(client kubernetes.Interface, informers *util.InformerManager, _ <-chan struct{}) *networkPolicyController {
	npc := &networkPolicyController{
		client:    client,
		informers: informers,

		namespaceLister:     informers.Core().V1().Namespaces().Lister(),
		podLister:           informers.Core().V1().Pods().Lister(),
		networkPolicyLister: informers.Networking().V1().NetworkPolicies().Lister(),

		updates: make(chan struct{}, 1),
	}

	// Record the informers we need; their caches will be synced before Start() is called.
	informers.Use(informers.Core().V1().Namespaces().Informer())
	informers.Use(informers.Core().V1().Pods().Informer())
	informers.Use(informers.Networking().V1().NetworkPolicies().Informer())

	return npc
}

func (npc *networkPolicyController) Run() {
	npc.Lock()
	defer npc.Unlock()

	npc.informers.AddEventHandler(npc.informers.Core().V1().Namespaces().Informer(),
		&v1.Namespace{}, npc.handleAddOrUpdateNamespace, npc.handleDeleteNamespace)
	npc.informers.AddEventHandler(npc.informers.Core().V1().Pods().Informer(),
		&v1.Pod{}, npc.handleAddOrUpdatePod, npc.handleDeletePod)
	npc.informers.AddEventHandler(npc.informers.Networking().V1().NetworkPolicies().Informer(),
		&networkingv1.NetworkPolicy{}, npc.handleAddOrUpdateNetworkPolicy, npc.handleDeleteNetworkPolicy)
}

// Updates returns a channel that will be selectable when an updated NetworkPolicy state
// is available
func (npc *networkPolicyController) Updates() <-chan struct{} {
	return npc.updates
}

// GetNetworkPolicies returns the current set of NetworkPolicies. FIXME we eventually
// need a better (eg, incremental) interface
func (npc *networkPolicyController) GetNetworkPolicies() []*networkPolicy {
	npc.Lock()
	defer npc.Unlock()

	return npc.policies
}

func (npc *networkPolicyController) handleAddOrUpdateNamespace(obj, old interface{}) {
	ns := obj.(*v1.Namespace)
	klog.V(4).InfoS("Add/Update Namespace", "namespace", klog.KObj(ns))

	if old != nil {
		oldNs := old.(*v1.Namespace)
		if reflect.DeepEqual(ns.Labels, oldNs.Labels) {
			return
		}
	}

	npc.Lock()
	defer npc.Unlock()
	npc.recompute()
}

func (npc *networkPolicyController) handleDeleteNamespace(obj interface{}) {
	ns := obj.(*v1.Namespace)
	klog.V(4).InfoS("Delete Namespace", "namespace", klog.KObj(ns))

	npc.Lock()
	defer npc.Unlock()
	npc.recompute()
}


func isOnPodNetwork(pod *v1.Pod) bool {
	if pod.Spec.HostNetwork {
		return false
	}
	return len(pod.Status.PodIPs) != 0
}

func (npc *networkPolicyController) handleAddOrUpdatePod(obj, old interface{}) {
	pod := obj.(*v1.Pod)
	klog.V(4).InfoS("Add/Update Pod", "pod", klog.KObj(pod))

	if !isOnPodNetwork(pod) {
		return
	}

	if old != nil {
		oldPod := old.(*v1.Pod)
		if reflect.DeepEqual(oldPod.Status.PodIPs, pod.Status.PodIPs) && reflect.DeepEqual(oldPod.Labels, pod.Labels) {
			return
		}
	}

	npc.Lock()
	defer npc.Unlock()
	npc.recompute()
}

func (npc *networkPolicyController) handleDeletePod(obj interface{}) {
	pod := obj.(*v1.Pod)
	klog.V(4).InfoS("Delete Pod", "pod", klog.KObj(pod))

	npc.Lock()
	defer npc.Unlock()
	npc.recompute()
}

func (npc *networkPolicyController) handleAddOrUpdateNetworkPolicy(obj, _ interface{}) {
	policy := obj.(*networkingv1.NetworkPolicy)
	klog.V(4).InfoS("Add/Update NetworkPolicy", "networkpolicy", klog.KObj(policy))

	npc.Lock()
	defer npc.Unlock()
	npc.recompute()
}

func (npc *networkPolicyController) handleDeleteNetworkPolicy(obj interface{}) {
	policy := obj.(*networkingv1.NetworkPolicy)
	klog.V(4).InfoS("Delete NetworkPolicy", "networkpolicy", klog.KObj(policy))

	npc.Lock()
	defer npc.Unlock()
	npc.recompute()
}

func (npc *networkPolicyController) selectPodsFromNamespaces(nsLabelSel, podLabelSel *metav1.LabelSelector) []*v1.Pod {
	var matchedPods []*v1.Pod

	nsSel, err := metav1.LabelSelectorAsSelector(nsLabelSel)
	if err != nil {
		// Shouldn't be possible
		return nil
	}

	podSel, err := metav1.LabelSelectorAsSelector(podLabelSel)
	if err != nil {
		// Shouldn't be possible
		return nil
	}

	namespaces, err := npc.namespaceLister.List(nsSel)
	if err != nil {
		// Shouldn't happen
		klog.ErrorS(err, "Could not list namespaces")
		return nil
	}

	for _, ns := range namespaces {
		pods, err := npc.podLister.Pods(ns.Name).List(podSel)
		if err != nil {
			// Shouldn't happen
			klog.ErrorS(err, "Could not find matching pods", "namespace", ns)
			continue
		}
		for _, pod := range pods {
			if isOnPodNetwork(pod) {
				matchedPods = append(matchedPods, pod)
			}
		}
	}

	return matchedPods
}

func (npc *networkPolicyController) selectPods(namespace string, lsel *metav1.LabelSelector) []*v1.Pod {
	var matchedPods []*v1.Pod

	sel, err := metav1.LabelSelectorAsSelector(lsel)
	if err != nil {
		// Shouldn't be possible
		return nil
	}

	pods, err := npc.podLister.Pods(namespace).List(sel)
	if err != nil {
		// Shouldn't happen
		klog.ErrorS(err, "Could not find matching pods", "namespace", namespace)
		return nil
	}
	for _, pod := range pods {
		if isOnPodNetwork(pod) {
			matchedPods = append(matchedPods, pod)
		}
	}
	return matchedPods
}

// parsePeers parses an array of NetworkPolicyPeer into a *networkPolicyPeer. Each element
// of peers resolves to either a list of pods or a list of CIDRs. The pods/CIDRs of all of
// the elements of peers are gathered together into a single *networkPolicyPeer.
func (npc *networkPolicyController) parsePeers(namespace string, npp *networkPolicy, peers []networkingv1.NetworkPolicyPeer) *networkPolicyPeer {
	if len(peers) == 0 {
		// no restrictions based on peers
		return nil
	}

	pp := &networkPolicyPeer{}
	for _, peer := range peers {
		if peer.PodSelector != nil && peer.NamespaceSelector == nil {
			pp.pods = append(pp.pods, npc.selectPods(namespace, peer.PodSelector)...)
		} else if peer.NamespaceSelector != nil {
			podSel := peer.PodSelector
			if podSel == nil {
				// Non-nil NamespaceSelect + nil PodSelector means to select
				// all pods in the selected namespaces
				podSel = &metav1.LabelSelector{}
			}
			pp.pods = append(pp.pods, npc.selectPodsFromNamespaces(peer.NamespaceSelector, podSel)...)
		} else if peer.NamespaceSelector != nil && peer.PodSelector != nil {
			pp.pods = append(pp.pods, npc.selectPodsFromNamespaces(peer.NamespaceSelector, peer.PodSelector)...)
		} else if peer.IPBlock != nil {
			pp.cidrs = append(pp.cidrs, ranges.IPBlockToCIDRs(peer.IPBlock)...)
		}
	}

	return pp
}

// findPodPort finds a ContainerPort in pod with the given portName, returning 0 if there
// is no match.
func findPodPort(pod *v1.Pod, portName string) int32 {
	for _, container := range pod.Spec.Containers {
		for _, port := range container.Ports {
			if port.Name == portName {
				return port.ContainerPort
			}
		}
	}
	return 0
}

// parseRuleWithPeer parses a (possibly-empty) array of NetworkPolicyPort, given the
// *networkPolicyPeer to which those ports apply, returning an array of *networkPolicyRule
// that each contain a single *networkPolicyPort.
func (npc *networkPolicyController) parseRuleWithPeer(namespace string, npp *networkPolicy, peer *networkPolicyPeer, ports []networkingv1.NetworkPolicyPort) []*networkPolicyRule {
	var rules []*networkPolicyRule
	if len(ports) == 0 {
		// no restrictions based on ports
		rules = append(rules, &networkPolicyRule{peer: peer})
		return rules
	}

	// Integer ports first
	for _, port := range ports {
		if port.Port.Type != intstr.Int || port.EndPort != nil {
			continue
		}
		rules = append(rules, &networkPolicyRule{
			port: &networkPolicyPort{
				protocol: *port.Protocol,
				port:     uint16(port.Port.IntVal),
				portMask: math.MaxUint16,
			},
			peer: peer,
		})
	}

	// Then port ranges (which get converted to port+mask)
	for _, port := range ports {
		if port.Port.Type != intstr.Int || port.EndPort == nil {
			continue
		}
		for _, portMask := range ranges.PortRangeToPortMasks(int(port.Port.IntVal), int(*port.EndPort)) {
			rules = append(rules, &networkPolicyRule{
				port: &networkPolicyPort{
					protocol: *port.Protocol,
					port:     portMask.Port,
					portMask: portMask.Mask,
				},
				peer: peer,
			})
		}
	}

	// Match up named ports
	for _, port := range ports {
		if port.Port.Type != intstr.String {
			continue
		}
		portName := port.Port.StrVal
		peers := make(map[int32][]*v1.Pod)

		for _, pod := range peer.pods {
			matchedPort := findPodPort(pod, portName)
			if matchedPort != 0 {
				peers[matchedPort] = append(peers[matchedPort], pod)
			}
		}
		for matchedPort, pods := range peers {
			rules = append(rules, &networkPolicyRule{
				port: &networkPolicyPort{
					protocol: *port.Protocol,
					port:     uint16(matchedPort),
					portMask: math.MaxUint16,
				},
				peer: &networkPolicyPeer{
					pods: pods,
				},
			})
		}
	}

	return rules
}

// parseNetworkPolicy parses a NetworkPolicy into a networkPolicy
func (npc *networkPolicyController) parseNetworkPolicy(policy *networkingv1.NetworkPolicy) *networkPolicy {
	npp := &networkPolicy{policy: policy}

	for _, ptype := range policy.Spec.PolicyTypes {
		if ptype == networkingv1.PolicyTypeIngress {
			ingresses := make([]*networkPolicyRule, 0)
			npp.ingress = &ingresses
		} else if ptype == networkingv1.PolicyTypeEgress {
			egresses := make([]*networkPolicyRule, 0)
			npp.egress = &egresses
		}
	}

	npp.targets = npc.selectPods(policy.Namespace, &policy.Spec.PodSelector)

	if npp.ingress != nil {
		for _, rule := range policy.Spec.Ingress {
			pp := npc.parsePeers(policy.Namespace, npp, rule.From)
			*npp.ingress = append(*npp.ingress, npc.parseRuleWithPeer(policy.Namespace, npp, pp, rule.Ports)...)
		}
	}

	if npp.egress != nil {
		for _, rule := range policy.Spec.Egress {
			pp := npc.parsePeers(policy.Namespace, npp, rule.To)
			*npp.egress = append(*npp.egress, npc.parseRuleWithPeer(policy.Namespace, npp, pp, rule.Ports)...)
		}
	}

	return npp
}

func (npc *networkPolicyController) recompute() {
	policies, err := npc.networkPolicyLister.NetworkPolicies(v1.NamespaceAll).List(labels.Everything())
	if err != nil {
		klog.ErrorS(err, "Error listing NetworkPolicies")
		return
	}

	npc.policies = make([]*networkPolicy, len(policies))
	for i, policy := range policies {
		npc.policies[i] = npc.parseNetworkPolicy(policy)
	}

	// Write to the updates channel, but if it has already been signaled then don't
	// block trying to write again.
	select {
	case npc.updates <- struct{}{}:
	default:
	}
}

type PodNetworkPolicies struct {
	PodIP net.IP

	Ingress *[]PodNetworkPolicyPeer
	Egress *[]PodNetworkPolicyPeer
}

type PodNetworkPolicyPeer struct {
	Peer *net.IPNet

	Port     uint16
	PortMask uint16
	Protocol uint8
}

func (npc *networkPolicyController) GetPodNetworkPolicies() map[types.UID]*PodNetworkPolicies {
	npc.Lock()
	defer npc.Unlock()

	policies := make(map[types.UID]*PodNetworkPolicies)
	for _, npp := range npc.policies {
		for _, pod := range npp.targets {
			pp := policies[pod.UID]
			if pp == nil {
				pp = &PodNetworkPolicies{PodIP: net.ParseIP(pod.Status.PodIPs[0].IP)}
				policies[pod.UID] = pp
			}

			if npp.ingress != nil {
				if pp.Ingress == nil {
					pp.Ingress = &[]PodNetworkPolicyPeer{}
				}
				for _, rule := range *npp.ingress {
					*pp.Ingress = append(*pp.Ingress, podPeersFromRule(rule)...)
				}
			}
			if npp.egress != nil {
				if pp.Egress == nil {
					pp.Egress = &[]PodNetworkPolicyPeer{}
				}
				for _, rule := range *npp.egress {
					*pp.Egress = append(*pp.Egress, podPeersFromRule(rule)...)
				}
			}
		}
	}

	return policies
}

func podPeersFromRule(rule *networkPolicyRule) []PodNetworkPolicyPeer {
	var pp PodNetworkPolicyPeer

	if rule.port != nil {
		pp.Protocol = getProtocol(rule.port.protocol)
		pp.Port = rule.port.port
		pp.PortMask = rule.port.portMask
	}

	if rule.peer == nil {
		peers := make([]PodNetworkPolicyPeer, 0, 2)
		pp.Peer = &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
		peers = append(peers, pp)
		pp.Peer = &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}
		peers = append(peers, pp)
		return peers
	}

	peers := make([]PodNetworkPolicyPeer, 0, len(rule.peer.pods) + len(rule.peer.cidrs))

	for _, pod := range rule.peer.pods {
		pp.Peer = &net.IPNet{IP: net.ParseIP(pod.Status.PodIPs[0].IP), Mask: net.CIDRMask(32, 32)}
		peers = append(peers, pp)
	}
	for _, cidr := range rule.peer.cidrs {
		_, pp.Peer, _ = net.ParseCIDR(cidr)
		peers = append(peers, pp)
	}

	return peers
}

func getProtocol(protocol v1.Protocol) uint8 {
	switch protocol {
	case v1.ProtocolTCP:
		return unix.IPPROTO_TCP
	case v1.ProtocolUDP:
		return unix.IPPROTO_UDP
	case v1.ProtocolSCTP:
		return unix.IPPROTO_SCTP
	default:
		return 0
	}
}
