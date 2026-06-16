// envelope.go decodes the oslo.messaging notification wrapper and
// decides whether an event is a Neutron metadata change worth a
// reconcile. The agent never reads the event's payload — it re-fetches
// authoritative state from Neutron on the kick — so this only extracts
// the two routing fields.

package kafka

import (
	"encoding/json"
	"strings"
)

// osloEnvelope is the outer oslo.messaging wrapper. `oslo.message` is a
// JSON string (the payload is doubly-encoded), decoded separately into
// [innerMessage].
type osloEnvelope struct {
	Message string `json:"oslo.message"`
}

// innerMessage is the subset of the decoded oslo.message the consumer
// routes on: which resource event, and which service published it.
type innerMessage struct {
	EventType   string `json:"event_type"`
	PublisherID string `json:"publisher_id"`
}

// decodeEvent unwraps the doubly-encoded oslo envelope and returns the
// event_type and publisher_id. ok is false for a malformed message — the
// caller counts and skips it.
func decodeEvent(value []byte) (eventType, publisherID string, ok bool) {
	var env osloEnvelope
	if err := json.Unmarshal(value, &env); err != nil || env.Message == "" {
		return "", "", false
	}
	var inner innerMessage
	if err := json.Unmarshal([]byte(env.Message), &inner); err != nil {
		return "", "", false
	}
	return inner.EventType, inner.PublisherID, true
}

// isNeutronChange reports whether an event is a committed Neutron change
// to a resource the agent models: published by Neutron, a `.end`
// (committed) event, and one of the metadata resource types. Events from
// other services (Nova, Cinder) sharing the topic, `.start` events, and
// Neutron resources the agent ignores all return false.
func isNeutronChange(eventType, publisherID string) bool {
	if !strings.HasPrefix(publisherID, neutronPublisherPrefix) {
		return false
	}
	if !strings.HasSuffix(eventType, committedSuffix) {
		return false
	}
	for _, p := range metadataEventPrefixes {
		if strings.HasPrefix(eventType, p) {
			return true
		}
	}
	return false
}
