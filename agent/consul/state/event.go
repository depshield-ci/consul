package state

import (
	"errors"
	"sync"

	"github.com/hashicorp/consul/agent/consul/stream"
)

type EventPublisher struct {
	listeners map[stream.Topic]map[*stream.SubscribeRequest]chan stream.Event
	staged    []stream.Event
	lock      sync.RWMutex
}

func NewEventPublisher() *EventPublisher {
	return &EventPublisher{
		listeners: make(map[stream.Topic]map[*stream.SubscribeRequest]chan stream.Event),
	}
}

// PreparePublish gets an event ready to publish to any listeners on the relevant
// topics. This doesn't do the send, which happens when the memdb transaction has
// been committed.
func (e *EventPublisher) PreparePublish(events []stream.Event) error {
	e.lock.Lock()
	defer e.lock.Unlock()

	if e.staged != nil {
		return errors.New("event already staged for commit")
	}

	e.staged = events

	return nil
}

// Commit sends any staged events to the relevant listeners. This is called
// via txn.Defer to delay it from running until the transaction has been finalized.
func (e *EventPublisher) Commit() {
	e.lock.Lock()
	defer e.lock.Unlock()

	for _, event := range e.staged {
		for subscription, listener := range e.listeners[event.Topic] {
			// If this event doesn't pertain to the subset this subscription is listening for,
			// skip sending it. We'll probably need more nuanced logic here later.
			if subscription.Key != event.Key && subscription.Key != "" {
				continue
			}

			select {
			case listener <- event:
			default:
			}
		}
	}

	e.staged = nil
}

func (e *EventPublisher) Subscribe(subscription *stream.SubscribeRequest) <-chan stream.Event {
	ch := make(chan stream.Event, 32)

	e.lock.Lock()
	defer e.lock.Unlock()
	if topicListeners, ok := e.listeners[subscription.Topic]; ok {
		topicListeners[subscription] = ch
	} else {
		e.listeners[subscription.Topic] = map[*stream.SubscribeRequest]chan stream.Event{
			subscription: ch,
		}
	}

	return ch
}

func (e *EventPublisher) Unsubscribe(subscription *stream.SubscribeRequest) {
	e.lock.Lock()
	defer e.lock.Unlock()
	delete(e.listeners[subscription.Topic], subscription)
}
