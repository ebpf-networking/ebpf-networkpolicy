package controller

import (
	"context"
	"fmt"
	"math"
	"reflect"
	"testing"
	"time"

	"k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	utilwait "k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/ebpf-networking/ebpf-networkpolicy/pkg/util"
)

func newTestNPC() (*networkPolicyController, chan struct{}) {
	client := fake.NewSimpleClientset()
	informers := util.NewInformerManager(client)
	stopCh := make(chan struct{})

	npc := newNetworkPolicyController(client, informers, stopCh)
	informers.Start(stopCh)
	npc.Run()

	return npc, stopCh
}

func waitForEvent(npc *networkPolicyController, f func() bool) error {
	return utilwait.Poll(10*time.Millisecond, 1*time.Second, func() (bool, error) {
		npc.Lock()
		defer npc.Unlock()
		return f(), nil
	})
}

func uid(kind, namespace, name string) types.UID {
	if namespace == "" {
		return types.UID(kind + ":" + name)
	} else {
		return types.UID(kind + ":" + namespace + "/" + name)
	}
}

var testNamespaces = make(map[string]int)

func addNamespace(npc *networkPolicyController, name string, subnetID int, labels map[string]string) {
	testNamespaces[name] = subnetID
	ns := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: labels,
			UID:    uid("Namespace", "", name),
		},
	}
	_, err := npc.client.CoreV1().Namespaces().Create(context.TODO(), ns, metav1.CreateOptions{})
	if err != nil {
		panic(fmt.Sprintf("Unexpected error creating namespace %q: %v", name, err))
	}
	err = waitForEvent(npc, func() bool {
		cachedNS, _ := npc.namespaceLister.Get(name)
		return cachedNS != nil
	})
	if err != nil {
		panic(fmt.Sprintf("Unexpected error waiting for namespace %q: %v", name, err))
	}
}

func delNamespace(npc *networkPolicyController, name string) {
	err := npc.client.CoreV1().Namespaces().Delete(context.TODO(), name, metav1.DeleteOptions{})
	if err != nil {
		panic(fmt.Sprintf("Unexpected error deleting namespace %q: %v", name, err))
	}
	err = waitForEvent(npc, func() bool {
		cachedNS, _ := npc.namespaceLister.Get(name)
		return cachedNS == nil
	})
	if err != nil {
		panic(fmt.Sprintf("Unexpected error waiting for namespace %q: %v", name, err))
	}
}

func addNetworkPolicy(npc *networkPolicyController, policy *networkingv1.NetworkPolicy) {
	policy.UID = uid("NetworkPolicy", policy.Namespace, policy.Name)
	_, err := npc.client.NetworkingV1().NetworkPolicies(policy.Namespace).Create(context.TODO(), policy, metav1.CreateOptions{})
	if err != nil {
		panic(fmt.Sprintf("Unexpected error creating policy %q: %v", policy.Name, err))
	}
	err = waitForEvent(npc, func() bool {
		cachedNP, _ := npc.networkPolicyLister.NetworkPolicies(policy.Namespace).Get(policy.Name)
		return cachedNP != nil
	})
	if err != nil {
		panic(fmt.Sprintf("Unexpected error waiting for policy %q: %v", policy.Name, err))
	}
}

func updateNetworkPolicy(npc *networkPolicyController, policy *networkingv1.NetworkPolicy) {
	policy.UID = uid("NetworkPolicy", policy.Namespace, policy.Name)
	np, err := npc.client.NetworkingV1().NetworkPolicies(policy.Namespace).Update(context.TODO(), policy, metav1.UpdateOptions{})
	if err != nil {
		panic(fmt.Sprintf("Unexpected error updating policy %q: %v", policy.Name, err))
	}
	err = waitForEvent(npc, func() bool {
		cachedNP, _ := npc.networkPolicyLister.NetworkPolicies(policy.Namespace).Get(policy.Name)
		return reflect.DeepEqual(cachedNP, np)
	})
	if err != nil {
		panic(fmt.Sprintf("Unexpected error waiting for policy %q: %v", policy.Name, err))
	}
}

func delNetworkPolicy(npc *networkPolicyController, policy *networkingv1.NetworkPolicy) {
	err := npc.client.NetworkingV1().NetworkPolicies(policy.Namespace).Delete(context.TODO(), policy.Name, metav1.DeleteOptions{})
	if err != nil {
		panic(fmt.Sprintf("Unexpected error deleting policy %q: %v", policy.Name, err))
	}
	err = waitForEvent(npc, func() bool {
		cachedNP, _ := npc.networkPolicyLister.NetworkPolicies(policy.Namespace).Get(policy.Name)
		return cachedNP == nil
	})
	if err != nil {
		panic(fmt.Sprintf("Unexpected error waiting for policy %q: %v", policy.Name, err))
	}
}

func clientIP(namespace string) string {
	subnet, exists := testNamespaces[namespace]
	if !exists {
		subnet = len(testNamespaces)
		testNamespaces[namespace] = subnet
	}

	return fmt.Sprintf("10.%d.0.2", subnet)
}

func serverIP(namespace string) string {
	subnet, exists := testNamespaces[namespace]
	if !exists {
		subnet = len(testNamespaces)
		testNamespaces[namespace] = subnet
	}

	return fmt.Sprintf("10.%d.0.99", subnet)
}

func addPods(npc *networkPolicyController, namespace string) {
	client := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      "client",
			UID:       uid("Pod", namespace, "client"),
			Labels: map[string]string{
				"kind": "client",
			},
		},
		Status: v1.PodStatus{
			PodIP: clientIP(namespace),
			PodIPs: []v1.PodIP{{IP: clientIP(namespace)}},
		},
	}

	server := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      "server",
			UID:       uid("Pod", namespace, "server"),
			Labels: map[string]string{
				"kind": "server",
			},
		},
		Status: v1.PodStatus{
			PodIP: serverIP(namespace),
			PodIPs: []v1.PodIP{{IP: serverIP(namespace)}},
		},
	}

	_, err := npc.client.CoreV1().Pods(namespace).Create(context.TODO(), client, metav1.CreateOptions{})
	if err != nil {
		panic(fmt.Sprintf("Unexpected error creating client pod: %v", err))
	}
	_, err = npc.client.CoreV1().Pods(namespace).Create(context.TODO(), server, metav1.CreateOptions{})
	if err != nil {
		panic(fmt.Sprintf("Unexpected error creating server pod: %v", err))
	}

	err = waitForEvent(npc, func() bool {
		clientPod, _ := npc.podLister.Pods(namespace).Get("client")
		serverPod, _ := npc.podLister.Pods(namespace).Get("server")
		return clientPod != nil && serverPod != nil
	})
	if err != nil {
		panic(fmt.Sprintf("Unexpected error waiting for pods in %q: %v", namespace, err))
	}
}

func addBadPods(npc *networkPolicyController, namespace string) {
	// HostNetwork pods should not show up in NetworkPolicies
	hostNetwork := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      "hostNetwork",
			UID:       uid("Pod", namespace, "hostNetwork"),
			Labels: map[string]string{
				"kind": "client",
			},
		},
		Spec: v1.PodSpec{
			HostNetwork: true,
		},
		Status: v1.PodStatus{
			PodIP: "1.2.3.4",
			PodIPs: []v1.PodIP{{IP: "1.2.3.4"}},
		},
	}

	// Pods that haven't yet received a PodIP should not show up
	pending := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      "pending",
			UID:       uid("Pod", namespace, "pending"),
			Labels: map[string]string{
				"kind": "client",
			},
		},
		Status: v1.PodStatus{
			Phase: v1.PodPending,
			PodIP: "",
			PodIPs: []v1.PodIP{},
		},
	}

	_, err := npc.client.CoreV1().Pods(namespace).Create(context.TODO(), hostNetwork, metav1.CreateOptions{})
	if err != nil {
		panic(fmt.Sprintf("Unexpected error creating hostNetwork pod: %v", err))
	}
	_, err = npc.client.CoreV1().Pods(namespace).Create(context.TODO(), pending, metav1.CreateOptions{})
	if err != nil {
		panic(fmt.Sprintf("Unexpected error creating pending pod: %v", err))
	}

	err = waitForEvent(npc, func() bool {
		hnPod, _ := npc.podLister.Pods(namespace).Get("hostNetwork")
		pendingPod, _ := npc.podLister.Pods(namespace).Get("pending")
		return hnPod != nil && pendingPod != nil
	})
	if err != nil {
		panic(fmt.Sprintf("Unexpected error waiting for bad pods in %q: %v", namespace, err))
	}
}

func portToString(port *networkPolicyPort) string {
	if port == nil {
		return ""
	} else if port.portMask != math.MaxUint16 {
		return fmt.Sprintf(" (%s %04x/%04x)", port.protocol, port.port, port.portMask)
	} else {
		return fmt.Sprintf(" (%s %d)", port.protocol, port.port)
	}
}

func policyToStrings(np *networkPolicy) []string {
	var strings []string

	for _, pod := range np.targets {
		if len(pod.Status.PodIPs) == 0 {
			continue
		}
		if np.ingress != nil {
			for _, rule := range *np.ingress {
				ports := portToString(rule.port)
				for _, srcPod := range rule.peer.pods {
					src := srcPod.Name
					if srcPod.Namespace != pod.Namespace {
						src = srcPod.Namespace+"/"+srcPod.Name
					}
					strings = append(strings, fmt.Sprintf("%s%s ingress from %s", pod.Name, ports, src))
				}
				for _, srcCIDR := range rule.peer.cidrs {
					strings = append(strings, fmt.Sprintf("%s%s ingress from %s", pod.Name, ports, srcCIDR))
				}
			}
		}
		if np.egress != nil {
			for _, rule := range *np.egress {
				ports := portToString(rule.port)
				for _, dstPod := range rule.peer.pods {
					dst := dstPod.Name
					if dstPod.Namespace != pod.Namespace {
						dst = dstPod.Namespace+"/"+dstPod.Name
					}
					strings = append(strings, fmt.Sprintf("%s egress to %s%s", pod.Name, dst, ports))
				}
				for _, dstCIDR := range rule.peer.cidrs {
					strings = append(strings, fmt.Sprintf("%s egress to %s%s", pod.Name, dstCIDR, ports))
				}
			}
		}
	}
	return strings
}

// Check some or all policies in namespace. This requires that (a) namespace has exactly
// nPolicies policies, and (b) every policy named in matches exists in the namespace
// exactly as specified. It does not require that matches lists every policy in the
// namespace; any extra policies that aren't in matches will just be ignored (other than
// the fact that nPolicies must still be correct).
func assertPolicies(npc *networkPolicyController, namespace string, nPolicies int, matches map[string][]string) error {
	npc.Lock()
	defer npc.Unlock()

	var foundPolicies int
	var matched []string
	for _, np := range npc.policies {
		if np.policy.Namespace != namespace {
			continue
		}
		foundPolicies++

		match := matches[np.policy.Name]
		if match == nil {
			continue
		}
		matchSet := sets.NewString(match...)
		matched = append(matched, np.policy.Name)

		policyStrings := policyToStrings(np)
		policySet := sets.NewString(policyStrings...)
		if !matchSet.Equal(policySet) {
			return fmt.Errorf("policy %q in %q has incorrect rules; expected %#v, got %#v", np.policy.Name, namespace, matchSet.List(), policySet.List())
		}
	}

	if len(matches) != len(matched) {
		return fmt.Errorf("expected namespace %q to match %d policies but only found %d %v", namespace, len(matches), len(matched), matched)
	}
	if foundPolicies != nPolicies {
		return fmt.Errorf("expected namespace %q to have %d policies but it has %d", namespace, nPolicies, foundPolicies)
	}

	return nil
}

func assertIngressRules(npc *networkPolicyController, rules map[string][]string) error {
	matchedRules := sets.NewString()
	ingressRules, _ := npc.GetPodNetworkPolicies()

	for podIP, podRules := range ingressRules {
		expected := rules[podIP]
		if expected == nil {
			continue
		}
		matchedRules.Insert(podIP)

		assertedRules := sets.NewString(expected...)
		actualRules := sets.NewString("isolated for ingress")
		for _, br := range podRules {
			// FIXME ports
			actualRules.Insert(fmt.Sprintf("ingress from %s", br.Peer))
		}

		if !actualRules.Equal(assertedRules) {
			return fmt.Errorf("pods[%s] expected %v got %v", podIP, assertedRules.List(), actualRules.List())
		}
	}

	if len(matchedRules) != len(rules) {
		assertedRules := sets.NewString()
		for podIP := range rules {
			assertedRules.Insert(podIP)
		}
		return fmt.Errorf("some rules were not matched: %v", assertedRules.Difference(matchedRules).List())
	}

	return nil
}

func assertEgressRules(npc *networkPolicyController, rules map[string][]string) error {
	matchedRules := sets.NewString()
	_, egressRules := npc.GetPodNetworkPolicies()

	for podIP, podRules := range egressRules {
		expected := rules[podIP]
		if expected == nil {
			continue
		}
		matchedRules.Insert(podIP)

		assertedRules := sets.NewString(expected...)
		actualRules := sets.NewString("isolated for egress")
		for _, br := range podRules {
			// FIXME ports
			actualRules.Insert(fmt.Sprintf("egress to %s", br.Peer))
		}

		if !actualRules.Equal(assertedRules) {
			return fmt.Errorf("pods[%s] expected %v got %v", podIP, assertedRules.List(), actualRules.List())
		}
	}

	if len(matchedRules) != len(rules) {
		assertedRules := sets.NewString()
		for podIP := range rules {
			assertedRules.Insert(podIP)
		}
		return fmt.Errorf("some rules were not matched: %v", assertedRules.Difference(matchedRules).List())
	}

	return nil
}

// FIXME! This test was adapted from openshift-sdn, and so the specific things it tests
// don't always make sense given the way NetworkPolicy is implemented here. (The test
// cases are both incomplete and redundant.)
func TestNetworkPolicy(t *testing.T) {
	npc, stopCh := newTestNPC()
	defer close(stopCh)

	// Create some Namespaces
	addNamespace(npc, "default", 0, map[string]string{"default": "true"})
	addNamespace(npc, "one", 1, map[string]string{"parity": "odd"})
	addNamespace(npc, "two", 2, map[string]string{"parity": "even", "prime": "true"})
	addNamespace(npc, "three", 3, map[string]string{"parity": "odd", "prime": "true"})
	addNamespace(npc, "four", 4, map[string]string{"parity": "even"})
	addNamespace(npc, "five", 5, map[string]string{"parity": "odd", "prime": "true"})

	// Add allow-from-self and allow-from-default policies to all
	for namespace := range testNamespaces {
		addNetworkPolicy(npc, &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "allow-from-self",
				Namespace: namespace,
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				Ingress: []networkingv1.NetworkPolicyIngressRule{{
					From: []networkingv1.NetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{},
					}},
				}},
			},
		})

		addNetworkPolicy(npc, &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "allow-from-default",
				Namespace: namespace,
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{},
				PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				Ingress: []networkingv1.NetworkPolicyIngressRule{{
					From: []networkingv1.NetworkPolicyPeer{{
						NamespaceSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"default": "true",
							},
						},
					}},
				}},
			},
		})
	}

	// Each namespace should now have 2 policies, but with no matching pods or rules
	for namespace := range testNamespaces {
		err := assertPolicies(npc, namespace, 2, map[string][]string{
			"allow-from-self": []string{},
			"allow-from-default": []string{},
		})
		if err != nil {
			t.Error(err.Error())
		}
	}
	err := assertIngressRules(npc, map[string][]string{})
	if err != nil {
		t.Error(err.Error())
	}

	// Add two pods to each namespace (except default)
	for namespace := range testNamespaces {
		if namespace == "default" {
			continue
		}

		addPods(npc, namespace)

		// That should fill in rules for the "allow-from-self", but nothing for
		// "allow-from-default" still because there are no pods there.
		err := assertPolicies(npc, namespace, 2, map[string][]string{
			"allow-from-self": []string{
				"client ingress from client",
				"client ingress from server",
				"server ingress from client",
				"server ingress from server",
			},
			"allow-from-default": []string{},
		})
		if err != nil {
			t.Error(err.Error())
		}
	}

	err = assertIngressRules(npc, map[string][]string{
		// one/client
		"10.1.0.2": []string{
			"isolated for ingress",
			"ingress from 10.1.0.2/32",
			"ingress from 10.1.0.99/32",
		},
		// one/server
		"10.1.0.99": []string{
			"isolated for ingress",
			"ingress from 10.1.0.2/32",
			"ingress from 10.1.0.99/32",
		},
		// two/client
		"10.2.0.2": []string{
			"isolated for ingress",
			"ingress from 10.2.0.2/32",
			"ingress from 10.2.0.99/32",
		},
		// two/server
		"10.2.0.99": []string{
			"isolated for ingress",
			"ingress from 10.2.0.2/32",
			"ingress from 10.2.0.99/32",
		},
		// etc
		"10.3.0.2": []string{
			"isolated for ingress",
			"ingress from 10.3.0.2/32",
			"ingress from 10.3.0.99/32",
		},
		"10.3.0.99": []string{
			"isolated for ingress",
			"ingress from 10.3.0.2/32",
			"ingress from 10.3.0.99/32",
		},
		"10.4.0.2": []string{
			"isolated for ingress",
			"ingress from 10.4.0.2/32",
			"ingress from 10.4.0.99/32",
		},
		"10.4.0.99": []string{
			"isolated for ingress",
			"ingress from 10.4.0.2/32",
			"ingress from 10.4.0.99/32",
		},
		"10.5.0.2": []string{
			"isolated for ingress",
			"ingress from 10.5.0.2/32",
			"ingress from 10.5.0.99/32",
		},
		"10.5.0.99": []string{
			"isolated for ingress",
			"ingress from 10.5.0.2/32",
			"ingress from 10.5.0.99/32",
		},
	})
	if err != nil {
		t.Error(err.Error())
	}

	// Allow all pods in even-numbered namespaces to connect to any pod in namespace "one"
	addNetworkPolicy(npc, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-from-even",
			Namespace: "one",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"parity": "even",
						},
					},
				}},
			}},
		},
	})

	err = assertPolicies(npc, "one", 3, map[string][]string{
		"allow-from-even": []string{
			"client ingress from two/client",
			"client ingress from two/server",
			"server ingress from two/client",
			"server ingress from two/server",
			"client ingress from four/client",
			"client ingress from four/server",
			"server ingress from four/client",
			"server ingress from four/server",
		},
	})
	if err != nil {
		t.Error(err.Error())
	}
	err = assertIngressRules(npc, map[string][]string{
		// one/client
		"10.1.0.2": []string{
			"isolated for ingress",
			"ingress from 10.1.0.2/32",
			"ingress from 10.1.0.99/32",
			"ingress from 10.2.0.2/32",
			"ingress from 10.2.0.99/32",
			"ingress from 10.4.0.2/32",
			"ingress from 10.4.0.99/32",
		},
		// one/server
		"10.1.0.99": []string{
			"isolated for ingress",
			"ingress from 10.1.0.2/32",
			"ingress from 10.1.0.99/32",
			"ingress from 10.2.0.2/32",
			"ingress from 10.2.0.99/32",
			"ingress from 10.4.0.2/32",
			"ingress from 10.4.0.99/32",
		},
	})
	if err != nil {
		t.Error(err.Error())
	}

	// Allow client pods in odd prime namespaces to connect to the server in namespace "one"
	addNetworkPolicy(npc, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-from-odd-primes",
			Namespace: "one",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"kind": "server",
				},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"parity": "odd",
							"prime":  "true",
						},
					},
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"kind": "client",
						},
					},
				}},
			}},
		},
	})

	err = assertPolicies(npc, "one", 4, map[string][]string{
		"allow-from-odd-primes": []string{
			"server ingress from three/client",
			"server ingress from five/client",
		},
	})
	if err != nil {
		t.Error(err.Error())
	}
	err = assertIngressRules(npc, map[string][]string{
		// one/client
		"10.1.0.2": []string{
			"isolated for ingress",
			"ingress from 10.1.0.2/32",
			"ingress from 10.1.0.99/32",
			"ingress from 10.2.0.2/32",
			"ingress from 10.2.0.99/32",
			"ingress from 10.4.0.2/32",
			"ingress from 10.4.0.99/32",
		},
		// one/server
		"10.1.0.99": []string{
			"isolated for ingress",
			"ingress from 10.1.0.2/32",
			"ingress from 10.1.0.99/32",
			"ingress from 10.2.0.2/32",
			"ingress from 10.2.0.99/32",
			"ingress from 10.3.0.2/32",
			"ingress from 10.4.0.2/32",
			"ingress from 10.4.0.99/32",
			"ingress from 10.5.0.2/32",
		},
	})
	if err != nil {
		t.Error(err.Error())
	}

	// Allow client pods in all namespaces to connect to the server in namespace "two"
	addNetworkPolicy(npc, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-from-all-clients",
			Namespace: "two",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"kind": "server",
				},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					NamespaceSelector: &metav1.LabelSelector{},
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"kind": "client",
						},
					},
				}},
			}},
		},
	})

	err = assertPolicies(npc, "two", 3, map[string][]string{
		"allow-from-all-clients": []string{
			"server ingress from one/client",
			"server ingress from client",
			"server ingress from three/client",
			"server ingress from four/client",
			"server ingress from five/client",
		},
	})
	if err != nil {
		t.Error(err.Error())
	}
	err = assertIngressRules(npc, map[string][]string{
		"10.2.0.2": []string{
			"isolated for ingress",
			"ingress from 10.2.0.2/32",
			"ingress from 10.2.0.99/32",
		},
		"10.2.0.99": []string{
			"isolated for ingress",
			"ingress from 10.1.0.2/32",
			"ingress from 10.2.0.2/32",
			"ingress from 10.2.0.99/32",
			"ingress from 10.3.0.2/32",
			"ingress from 10.4.0.2/32",
			"ingress from 10.5.0.2/32",
		},
	})
	if err != nil {
		t.Error(err.Error())
	}

	// add some more namespaces
	addNamespace(npc, "six", 6, map[string]string{"parity": "even"})
	addPods(npc, "six")
	addNamespace(npc, "seven", 7, map[string]string{"parity": "odd", "prime": "true"})
	addPods(npc, "seven")
	addNamespace(npc, "eight", 8, map[string]string{"parity": "even"})
	addPods(npc, "eight")
	addNamespace(npc, "nine", 9, map[string]string{"parity": "odd"})
	addPods(npc, "nine")

	// add some non-pod-network pods; this should not affect the generated flows.
	addBadPods(npc, "four")
	addBadPods(npc, "seven")
	addBadPods(npc, "nine")

	// Now reassert the full set of matches for each namespace
	for namespace, id := range testNamespaces {
		switch id {
		case 0:
			err := assertPolicies(npc, namespace, 2, map[string][]string{
				"allow-from-self": []string{},
				"allow-from-default": []string{},
			})
			if err != nil {
				t.Error(err.Error())
			}

		case 1:
			err := assertPolicies(npc, namespace, 4, map[string][]string{
				"allow-from-self": []string{
					"client ingress from client",
					"client ingress from server",
					"server ingress from client",
					"server ingress from server",
				},
				"allow-from-default": []string{},
				"allow-from-even": []string{
					"client ingress from two/client",
					"client ingress from two/server",
					"server ingress from two/client",
					"server ingress from two/server",
					"client ingress from four/client",
					"client ingress from four/server",
					"server ingress from four/client",
					"server ingress from four/server",
					"client ingress from six/client",
					"client ingress from six/server",
					"server ingress from six/client",
					"server ingress from six/server",
					"client ingress from eight/client",
					"client ingress from eight/server",
					"server ingress from eight/client",
					"server ingress from eight/server",
				},
				"allow-from-odd-primes": []string{
					"server ingress from three/client",
					"server ingress from five/client",
					"server ingress from seven/client",
				},
			})
			if err != nil {
				t.Error(err.Error())
			}

		case 2:
			err := assertPolicies(npc, namespace, 3, map[string][]string{
				"allow-from-self": []string{
					"client ingress from client",
					"client ingress from server",
					"server ingress from client",
					"server ingress from server",
				},
				"allow-from-default": []string{},
				"allow-from-all-clients": []string{
					"server ingress from one/client",
					"server ingress from client",
					"server ingress from three/client",
					"server ingress from four/client",
					"server ingress from five/client",
					"server ingress from six/client",
					"server ingress from seven/client",
					"server ingress from eight/client",
					"server ingress from nine/client",
				},
			})
			if err != nil {
				t.Error(err.Error())
			}

		case 3, 4, 5:
			err := assertPolicies(npc, namespace, 2, map[string][]string{
				"allow-from-self": []string{
					fmt.Sprintf("client ingress from client"),
					fmt.Sprintf("client ingress from server"),
					fmt.Sprintf("server ingress from client"),
					fmt.Sprintf("server ingress from server"),
				},
				"allow-from-default": []string{},
			})
			if err != nil {
				t.Error(err.Error())
			}

		case 6, 7, 8, 9:
			err := assertPolicies(npc, namespace, 0, nil)
			if err != nil {
				t.Error(err.Error())
			}

		default:
			t.Errorf("Unexpected namespace %s", namespace)
		}
	}
	err = assertIngressRules(npc, map[string][]string{
		"10.1.0.2": []string{
			"isolated for ingress",
			"ingress from 10.1.0.2/32",
			"ingress from 10.1.0.99/32",
			"ingress from 10.2.0.2/32",
			"ingress from 10.2.0.99/32",
			"ingress from 10.4.0.2/32",
			"ingress from 10.4.0.99/32",
			"ingress from 10.6.0.2/32",
			"ingress from 10.6.0.99/32",
			"ingress from 10.8.0.2/32",
			"ingress from 10.8.0.99/32",
		},
		"10.1.0.99": []string{
			"isolated for ingress",
			"ingress from 10.1.0.2/32",
			"ingress from 10.1.0.99/32",
			"ingress from 10.2.0.2/32",
			"ingress from 10.2.0.99/32",
			"ingress from 10.3.0.2/32",
			"ingress from 10.4.0.2/32",
			"ingress from 10.4.0.99/32",
			"ingress from 10.5.0.2/32",
			"ingress from 10.6.0.2/32",
			"ingress from 10.6.0.99/32",
			"ingress from 10.7.0.2/32",
			"ingress from 10.8.0.2/32",
			"ingress from 10.8.0.99/32",
		},

		"10.2.0.2": []string{
			"isolated for ingress",
			"ingress from 10.2.0.2/32",
			"ingress from 10.2.0.99/32",
		},
		"10.2.0.99": []string{
			"isolated for ingress",
			"ingress from 10.1.0.2/32",
			"ingress from 10.2.0.2/32",
			"ingress from 10.2.0.99/32",
			"ingress from 10.3.0.2/32",
			"ingress from 10.4.0.2/32",
			"ingress from 10.5.0.2/32",
			"ingress from 10.6.0.2/32",
			"ingress from 10.7.0.2/32",
			"ingress from 10.8.0.2/32",
			"ingress from 10.9.0.2/32",
		},

		"10.3.0.2": []string{
			"isolated for ingress",
			"ingress from 10.3.0.2/32",
			"ingress from 10.3.0.99/32",
		},
		"10.3.0.99": []string{
			"isolated for ingress",
			"ingress from 10.3.0.2/32",
			"ingress from 10.3.0.99/32",
		},
		"10.4.0.2": []string{
			"isolated for ingress",
			"ingress from 10.4.0.2/32",
			"ingress from 10.4.0.99/32",
		},
		"10.4.0.99": []string{
			"isolated for ingress",
			"ingress from 10.4.0.2/32",
			"ingress from 10.4.0.99/32",
		},
		"10.5.0.2": []string{
			"isolated for ingress",
			"ingress from 10.5.0.2/32",
			"ingress from 10.5.0.99/32",
		},
		"10.5.0.99": []string{
			"isolated for ingress",
			"ingress from 10.5.0.2/32",
			"ingress from 10.5.0.99/32",
		},
	})
	if err != nil {
		t.Error(err.Error())
	}

	// Delete a namespace
	delNamespace(npc, "four")
	err = assertPolicies(npc, "one", 4, map[string][]string{
		"allow-from-even": []string{
			"client ingress from two/client",
			"client ingress from two/server",
			"server ingress from two/client",
			"server ingress from two/server",
			"client ingress from six/client",
			"client ingress from six/server",
			"server ingress from six/client",
			"server ingress from six/server",
			"client ingress from eight/client",
			"client ingress from eight/server",
			"server ingress from eight/client",
			"server ingress from eight/server",
		},
	})
	if err != nil {
		t.Error(err.Error())
	}
	err = assertPolicies(npc, "two", 3, map[string][]string{
		"allow-from-all-clients": []string{
			"server ingress from one/client",
			"server ingress from client",
			"server ingress from three/client",
			"server ingress from five/client",
			"server ingress from six/client",
			"server ingress from seven/client",
			"server ingress from eight/client",
			"server ingress from nine/client",
		},
	})
	if err != nil {
		t.Error(err.Error())
	}

	err = assertIngressRules(npc, map[string][]string{
		"10.1.0.2": []string{
			"isolated for ingress",
			"ingress from 10.1.0.2/32",
			"ingress from 10.1.0.99/32",
			"ingress from 10.2.0.2/32",
			"ingress from 10.2.0.99/32",
			"ingress from 10.6.0.2/32",
			"ingress from 10.6.0.99/32",
			"ingress from 10.8.0.2/32",
			"ingress from 10.8.0.99/32",
		},
		"10.1.0.99": []string{
			"isolated for ingress",
			"ingress from 10.1.0.2/32",
			"ingress from 10.1.0.99/32",
			"ingress from 10.2.0.2/32",
			"ingress from 10.2.0.99/32",
			"ingress from 10.3.0.2/32",
			"ingress from 10.5.0.2/32",
			"ingress from 10.6.0.2/32",
			"ingress from 10.6.0.99/32",
			"ingress from 10.7.0.2/32",
			"ingress from 10.8.0.2/32",
			"ingress from 10.8.0.99/32",
		},

		"10.2.0.2": []string{
			"isolated for ingress",
			"ingress from 10.2.0.2/32",
			"ingress from 10.2.0.99/32",
		},
		"10.2.0.99": []string{
			"isolated for ingress",
			"ingress from 10.1.0.2/32",
			"ingress from 10.2.0.2/32",
			"ingress from 10.2.0.99/32",
			"ingress from 10.3.0.2/32",
			"ingress from 10.5.0.2/32",
			"ingress from 10.6.0.2/32",
			"ingress from 10.7.0.2/32",
			"ingress from 10.8.0.2/32",
			"ingress from 10.9.0.2/32",
		},
	})
	if err != nil {
		t.Error(err.Error())
	}
}

func TestNetworkPolicy_ipBlock(t *testing.T) {
	npc, stopCh := newTestNPC()
	defer close(stopCh)

	// Create a default Namespace
	addNamespace(npc, "default", 0, map[string]string{"default": "true"})
	addPods(npc, "default")

	// Add a simple ipBlock policy
	addNetworkPolicy(npc, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-from-cidr",
			Namespace: "default",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					IPBlock: &networkingv1.IPBlock{
						CIDR: "192.168.0.0/24",
					},
				}},
			}},
		},
	})

	err := assertPolicies(npc, "default", 1, map[string][]string{
		"allow-from-cidr": []string{
			"client ingress from 192.168.0.0/24",
			"server ingress from 192.168.0.0/24",
		},
	})
	if err != nil {
		t.Error(err.Error())
	}
	err = assertIngressRules(npc, map[string][]string{
		"10.0.0.2": []string{
			"isolated for ingress",
			"ingress from 192.168.0.0/24",
		},
		"10.0.0.99": []string{
			"isolated for ingress",
			"ingress from 192.168.0.0/24",
		},
	})
	if err != nil {
		t.Error(err.Error())
	}

	// Add a mixed ipBlock/podSelector policy
	addNetworkPolicy(npc, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-from-cidr-and-pods",
			Namespace: "default",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{
					{
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{
								"kind": "client",
							},
						},
					},
					{
						IPBlock: &networkingv1.IPBlock{
							CIDR: "192.168.1.0/24",
						},
					},
				},
			}},
		},
	})

	err = assertPolicies(npc, "default", 2, map[string][]string{
		"allow-from-cidr-and-pods": []string{
			"client ingress from 192.168.1.0/24",
			"server ingress from 192.168.1.0/24",
			"client ingress from client",
			"server ingress from client",
		},
	})
	if err != nil {
		t.Error(err.Error())
	}
	err = assertIngressRules(npc, map[string][]string{
		"10.0.0.2": []string{
			"isolated for ingress",
			"ingress from 192.168.0.0/24",
			"ingress from 192.168.1.0/24",
			"ingress from 10.0.0.2/32",
		},
		"10.0.0.99": []string{
			"isolated for ingress",
			"ingress from 192.168.0.0/24",
			"ingress from 192.168.1.0/24",
			"ingress from 10.0.0.2/32",
		},
	})
	if err != nil {
		t.Error(err.Error())
	}

	// Add a policy with multiple ipBlocks, including an "except" clause.
	addNetworkPolicy(npc, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-from-multiple-cidrs",
			Namespace: "default",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"kind": "server",
				},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					From: []networkingv1.NetworkPolicyPeer{
						{
							IPBlock: &networkingv1.IPBlock{
								CIDR: "192.168.0.0/24",
							},
						},
						{
							IPBlock: &networkingv1.IPBlock{
								CIDR: "192.168.2.0/24",
								Except: []string{
									"192.168.2.1/32",
								},
							},
						},
					},
				},
				{
					From: []networkingv1.NetworkPolicyPeer{
						{
							IPBlock: &networkingv1.IPBlock{
								CIDR: "192.168.10.0/24",
							},
						},
						{
							IPBlock: &networkingv1.IPBlock{
								CIDR: "192.168.20.0/24",
							},
						},
					},
				},
			},
		},
	})

	err = assertPolicies(npc, "default", 3, map[string][]string{
		"allow-from-multiple-cidrs": []string{
			"server ingress from 192.168.0.0/24",

			// rule with except gets exploded to multiple flows
			"server ingress from 192.168.2.128/25",
			"server ingress from 192.168.2.64/26",
			"server ingress from 192.168.2.32/27",
			"server ingress from 192.168.2.16/28",
			"server ingress from 192.168.2.8/29",
			"server ingress from 192.168.2.4/30",
			"server ingress from 192.168.2.2/31",
			"server ingress from 192.168.2.0/32",

			"server ingress from 192.168.10.0/24",
			"server ingress from 192.168.20.0/24",
		},
	})
	if err != nil {
		t.Error(err.Error())
	}
	err = assertIngressRules(npc, map[string][]string{
		"10.0.0.2": []string{
			"isolated for ingress",
			"ingress from 192.168.0.0/24",
			"ingress from 192.168.1.0/24",
			"ingress from 10.0.0.2/32",
		},
		"10.0.0.99": []string{
			"isolated for ingress",
			"ingress from 192.168.0.0/24",
			"ingress from 192.168.1.0/24",
			"ingress from 10.0.0.2/32",
			"ingress from 192.168.2.128/25",
			"ingress from 192.168.2.64/26",
			"ingress from 192.168.2.32/27",
			"ingress from 192.168.2.16/28",
			"ingress from 192.168.2.8/29",
			"ingress from 192.168.2.4/30",
			"ingress from 192.168.2.2/31",
			"ingress from 192.168.2.0/32",
			"ingress from 192.168.10.0/24",
			"ingress from 192.168.20.0/24",
		},
	})
	if err != nil {
		t.Error(err.Error())
	}
}

func TestNetworkPolicy_egress(t *testing.T) {
	npc, stopCh := newTestNPC()
	defer close(stopCh)

	// Create Namespaces
	addNamespace(npc, "default", 0, map[string]string{"default": "true"})
	addPods(npc, "default")
	addNamespace(npc, "one", 1, map[string]string{"parity": "odd"})
	addPods(npc, "one")
	addNamespace(npc, "two", 2, map[string]string{"parity": "even"})
	addPods(npc, "two")
	addNamespace(npc, "three", 3, map[string]string{"parity": "odd"})
	addPods(npc, "three")

	// Add ingress/egress default-deny
	addNetworkPolicy(npc, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default-deny",
			Namespace: "default",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{},
			Egress:  []networkingv1.NetworkPolicyEgressRule{},
		},
	})

	err := assertPolicies(npc, "default", 1, map[string][]string{
		"default-deny": []string{},
	})
	if err != nil {
		t.Error(err.Error())
	}
	err = assertIngressRules(npc, map[string][]string{
		"10.0.0.2": []string{
			"isolated for ingress",
		},
		"10.0.0.99": []string{
			"isolated for ingress",
		},
	})
	if err != nil {
		t.Error(err.Error())
	}
	err = assertEgressRules(npc, map[string][]string{
		"10.0.0.2": []string{
			"isolated for egress",
		},
		"10.0.0.99": []string{
			"isolated for egress",
		},
	})
	if err != nil {
		t.Error(err.Error())
	}

	// Add a just-egress policy
	addNetworkPolicy(npc, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "egress",
			Namespace: "default",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"kind": "client",
				},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			Egress: []networkingv1.NetworkPolicyEgressRule{{
				To: []networkingv1.NetworkPolicyPeer{{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"kind": "server",
						},
					},
				}},
			}},
		},
	})

	err = assertPolicies(npc, "default", 2, map[string][]string{
		"egress": []string{
			"client egress to server",
		},
	})
	if err != nil {
		t.Error(err.Error())
	}
	err = assertIngressRules(npc, map[string][]string{
		"10.0.0.2": []string{
			"isolated for ingress",
		},
		"10.0.0.99": []string{
			"isolated for ingress",
		},
	})
	if err != nil {
		t.Error(err.Error())
	}
	err = assertEgressRules(npc, map[string][]string{
		"10.0.0.2": []string{
			"isolated for egress",
			"egress to 10.0.0.99/32",
		},
		"10.0.0.99": []string{
			"isolated for egress",
		},
	})
	if err != nil {
		t.Error(err.Error())
	}

	// Add a mixed-ingress-egress policy
	addNetworkPolicy(npc, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ingress-egress",
			Namespace: "default",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"kind": "client",
						},
					},
				}},
			}},
			Egress: []networkingv1.NetworkPolicyEgressRule{{
				To: []networkingv1.NetworkPolicyPeer{{
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"parity": "odd",
						},
					},
				}},
			}},
		},
	})

	err = assertPolicies(npc, "default", 3, map[string][]string{
		"ingress-egress": []string{
			"client ingress from client",
			"server ingress from client",
			"client egress to one/client",
			"client egress to one/server",
			"server egress to one/client",
			"server egress to one/server",
			"client egress to three/client",
			"client egress to three/server",
			"server egress to three/client",
			"server egress to three/server",
		},
	})
	if err != nil {
		t.Error(err.Error())
	}
	err = assertIngressRules(npc, map[string][]string{
		"10.0.0.2": []string{
			"isolated for ingress",
			"ingress from 10.0.0.2/32",
		},
		"10.0.0.99": []string{
			"isolated for ingress",
			"ingress from 10.0.0.2/32",
		},
	})
	if err != nil {
		t.Error(err.Error())
	}
	err = assertEgressRules(npc, map[string][]string{
		"10.0.0.2": []string{
			"isolated for egress",
			"egress to 10.0.0.99/32",
			"egress to 10.1.0.2/32",
			"egress to 10.1.0.99/32",
			"egress to 10.3.0.2/32",
			"egress to 10.3.0.99/32",
		},
		"10.0.0.99": []string{
			"isolated for egress",
			"egress to 10.1.0.2/32",
			"egress to 10.1.0.99/32",
			"egress to 10.3.0.2/32",
			"egress to 10.3.0.99/32",
		},
	})
	if err != nil {
		t.Error(err.Error())
	}

	// Add NetworkPolicies to "two". In particular:
	//   - all pods are isolated for Ingress
	//   - Ingress is allowed to "server" only by the second policy
	//   - Egress is denied to some non-existent pod by the third policy.
	// The egress policy should have no effect.
	addNetworkPolicy(npc, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "default-deny-ingress",
			Namespace: "two",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{},
		},
	})
	addNetworkPolicy(npc, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-client-to-server",
			Namespace: "two",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"kind": "server",
				},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"kind": "client",
						},
					},
				}},
			}},
		},
	})
	addNetworkPolicy(npc, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "irrelevant-egress",
			Namespace: "two",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"kind": "nonexistent",
				},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeEgress,
			},
			Egress: []networkingv1.NetworkPolicyEgressRule{},
		},
	})

	err = assertPolicies(npc, "two", 3, map[string][]string{
		"default-deny-ingress": []string{},
		"allow-client-to-server": []string{
			"server ingress from client",
		},
		"irrelevant-egress": []string{},
	})
	if err != nil {
		t.Error(err.Error())
	}
	err = assertIngressRules(npc, map[string][]string{
		"10.2.0.2": []string{
			"isolated for ingress",
		},
		"10.2.0.99": []string{
			"isolated for ingress",
			"ingress from 10.2.0.2/32",
		},
	})
	if err != nil {
		t.Error(err.Error())
	}
	err = assertEgressRules(npc, map[string][]string{})
	if err != nil {
		t.Error(err.Error())
	}

	// Add NetworkPolicies to "three":
	//   - Ingress is allowed to "server" only by one policy
	//   - Egress is allowed to "server" only by a different policy
	// Make sure that this allows both ingress and egress...
	addNetworkPolicy(npc, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "server-ingress",
			Namespace: "three",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"kind": "server",
				},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"kind": "client",
						},
					},
				}},
			}},
		},
	})
	addNetworkPolicy(npc, &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "server-egress",
			Namespace: "three",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"kind": "server",
				},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeEgress,
			},
			Egress: []networkingv1.NetworkPolicyEgressRule{{
				To: []networkingv1.NetworkPolicyPeer{{
					PodSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"kind": "client",
						},
					},
				}},
			}},
		},
	})

	err = assertPolicies(npc, "three", 2, map[string][]string{
		"server-ingress": []string{
			"server ingress from client",
		},
		"server-egress": []string{
			"server egress to client",
		},
	})
	if err != nil {
		t.Error(err.Error())
	}
	err = assertIngressRules(npc, map[string][]string{
		"10.3.0.99": []string{
			"isolated for ingress",
			"ingress from 10.3.0.2/32",
		},
	})
	if err != nil {
		t.Error(err.Error())
	}
	err = assertEgressRules(npc, map[string][]string{
		"10.3.0.99": []string{
			"isolated for egress",
			"egress to 10.3.0.2/32",
		},
	})
	if err != nil {
		t.Error(err.Error())
	}
}
