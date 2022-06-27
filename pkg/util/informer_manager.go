package util

import (
	"reflect"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

type InformerManager struct {
	informers.SharedInformerFactory
	
	syncFuncs []cache.InformerSynced
}

var defaultInformerResyncPeriod = 30 * time.Minute

func NewInformerManager(client kubernetes.Interface) *InformerManager {
	return &InformerManager{
		SharedInformerFactory: informers.NewSharedInformerFactory(client, defaultInformerResyncPeriod),
	}
}

func (im *InformerManager) Use(informer cache.SharedIndexInformer) {
	im.syncFuncs = append(im.syncFuncs, informer.HasSynced)
}

func (im *InformerManager) Start(stopCh <-chan struct{}) bool {
	im.SharedInformerFactory.Start(stopCh)
	return cache.WaitForCacheSync(stopCh, im.syncFuncs...)
}

type InformerAddOrUpdateFunc func(interface{}, interface{})
type InformerDeleteFunc func(interface{})

func (im *InformerManager) AddEventHandler(informer cache.SharedIndexInformer, objType runtime.Object, addOrUpdateFunc InformerAddOrUpdateFunc, deleteFunc InformerDeleteFunc) {
	handlerFuncs := cache.ResourceEventHandlerFuncs{}
	if addOrUpdateFunc != nil {
		handlerFuncs.AddFunc = func(obj interface{}) {
			addOrUpdateFunc(obj, nil)
		}
		handlerFuncs.UpdateFunc = func(old, cur interface{}) {
			addOrUpdateFunc(cur, old)
		}
	}
	if deleteFunc != nil {
		handlerFuncs.DeleteFunc = func(obj interface{}) {
			if reflect.TypeOf(objType) != reflect.TypeOf(obj) {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					klog.Errorf("Couldn't get object from tombstone: %+v", obj)
					return
				}

				obj = tombstone.Obj
				if reflect.TypeOf(objType) != reflect.TypeOf(obj) {
					klog.Errorf("Tombstone contained object, expected resource type: %v but got: %v", reflect.TypeOf(objType), reflect.TypeOf(obj))
					return
				}
			}
			deleteFunc(obj)
		}
	}

	informer.AddEventHandler(handlerFuncs)
}
