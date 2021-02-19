package process

import (
	"github.com/open-policy-agent/gatekeeper/pkg/util"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"reflect"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sync"

	configv1alpha1 "github.com/open-policy-agent/gatekeeper/apis/config/v1alpha1"
	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
)

type Process string

const (
	Audit    = Process("audit")
	Sync     = Process("sync")
	Webhook  = Process("webhook")
	Mutation = Process("mutation-webhook")
	Star     = Process("*")
)

var log = logf.Log.WithName("excluder")

type Excluder struct {
	mux                sync.RWMutex
	excludedNamespaces map[Process]map[string]bool
	excludedNamespaceSelectors map[Process][]labels.Selector
}

var allProcesses = []Process{
	Audit,
	Webhook,
	Sync,
}

var processExcluder = &Excluder{
	excludedNamespaces: make(map[Process]map[string]bool),
	excludedNamespaceSelectors: make(map[Process][]labels.Selector),
}

func Get() *Excluder {
	return processExcluder
}

func New() *Excluder {
	return &Excluder{
		excludedNamespaces: make(map[Process]map[string]bool),
		excludedNamespaceSelectors: make(map[Process][]labels.Selector),
	}
}

func (s *Excluder) Add(entry []configv1alpha1.MatchEntry) {
	s.mux.Lock()
	defer s.mux.Unlock()

	for _, matchEntry := range entry {
		var processes []Process
		for _, op := range matchEntry.Processes {
			if Process(op) == Star {
				processes = allProcesses
				break
			}
			processes = append(processes, Process(op))
		}
		for _, p := range processes {
			log.Info("check matchEntry in","process", string(p))
			for _, ns := range matchEntry.ExcludedNamespaces {
				log.Info("check matchEntry.ExcludedNamespaces", "ExcludedNamespaces", ns)
				// adding excluded namespace to all processes for "*"
				if s.excludedNamespaces[p] == nil {
					s.excludedNamespaces[p] = make(map[string]bool)
				}
				s.excludedNamespaces[p][ns] = true
			}
			for _, ns := range matchEntry.NamespaceSelectors {
				log.Info("NamespaceSelectors:", "NamespaceSelectors", ns.String())
				for _, expr := range ns.MatchExpressions {
					log.Info("check expr.Operator ", "key", expr.Key, "op", expr.Operator)
					if expr.Operator == metav1.LabelSelectorOpDoesNotExist{
						selector, e := metav1.LabelSelectorAsSelector(ns)
						if e == nil {
							log.Info("exclude",  "selector", selector)
							s.excludedNamespaceSelectors[p] = append(s.excludedNamespaceSelectors[p], selector)
						} else {
							log.Error(e, "illegal namespaceSelectors format")
						}
					}
				}
			}
		}
	}
}

func (s *Excluder) Replace(new *Excluder) {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.excludedNamespaces = new.excludedNamespaces
	s.excludedNamespaceSelectors = new.excludedNamespaceSelectors
}

func (s *Excluder) Equals(new *Excluder) bool {
	s.mux.RLock()
	defer s.mux.RUnlock()
	return reflect.DeepEqual(s.excludedNamespaces, new.excludedNamespaces) && reflect.DeepEqual(s.excludedNamespaceSelectors, new.excludedNamespaceSelectors)
}

func (s *Excluder) IsNamespaceExcluded(process Process, obj runtime.Object) (bool, error) {
	s.mux.RLock()
	defer s.mux.RUnlock()

	meta, err := meta.Accessor(obj)
	if err != nil {
		return false, errors.Wrapf(err, "Failed to get accessor for %s - %s", obj.GetObjectKind().GroupVersionKind().Group, obj.GetObjectKind().GroupVersionKind().Kind)
	}

	if util.IsNamespace(obj) {
		return s.excludedNamespaces[process][meta.GetName()], nil
	}

	return s.excludedNamespaces[process][meta.GetNamespace()], nil
}

func (s *Excluder) IsNamespaceSelectorExcluded(process Process, obj runtime.Object, ns *corev1.Namespace) (bool, error) {
	s.mux.RLock()
	defer s.mux.RUnlock()

	meta, err := meta.Accessor(obj)
	if err != nil {
		return false, errors.Wrapf(err, "Failed to get accessor for %s - %s", obj.GetObjectKind().GroupVersionKind().Group, obj.GetObjectKind().GroupVersionKind().Kind)
	}
	for _, selector := range s.excludedNamespaceSelectors[process] {
		log.Info("comparing", "selector", selector)
		switch {
		case util.IsNamespace(obj):
			// if the object is a namespace, namespace selector matches against the object
			log.Info("IsNamespaceSelectorExcluded for ns", "ns", obj, "label", meta.GetLabels())
			log.Info("match", "?", selector.Matches(labels.Set(meta.GetLabels())))
			// selector is "!label", not matching tells the excluded label is add to the namespace
			if !selector.Matches(labels.Set(meta.GetLabels())) {
				return true, nil
			}
		case meta.GetNamespace() == "":
			// cluster scoped
		case !selector.Matches(labels.Set(ns.Labels)):
			log.Info("IsNamespaceSelectorExcluded for obj", "obj", meta.GetName(),"ns.Labels", ns.Labels)
			return true, nil
		}
	}
	return false, nil
}
