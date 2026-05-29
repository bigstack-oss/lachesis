package netlink

import (
	"reflect"
	"sync"
	"testing"
)

func TestRegistry_HappyPath(t *testing.T) {
	r := NewRegistry()
	if r.Len() != 0 {
		t.Fatalf("new registry: Len = %d, want 0", r.Len())
	}
	if r.IsAttached("tap0") {
		t.Fatal("new registry: tap0 unexpectedly attached")
	}
	r.MarkAttached("tap0")
	r.MarkAttached("tap1")
	if r.Len() != 2 {
		t.Fatalf("after 2 marks: Len = %d, want 2", r.Len())
	}
	if !r.IsAttached("tap0") || !r.IsAttached("tap1") {
		t.Error("expected tap0 and tap1 to be attached")
	}
	if got, want := r.Snapshot(), []string{"tap0", "tap1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Snapshot = %v, want %v", got, want)
	}
}

func TestRegistry_Idempotent(t *testing.T) {
	r := NewRegistry()
	r.MarkAttached("tap0")
	r.MarkAttached("tap0")
	if r.Len() != 1 {
		t.Errorf("after duplicate MarkAttached: Len = %d, want 1", r.Len())
	}
	r.Forget("tap0")
	r.Forget("tap0")
	if r.Len() != 0 {
		t.Errorf("after duplicate Forget: Len = %d, want 0", r.Len())
	}
	r.Forget("never-added")
	if r.Len() != 0 {
		t.Errorf("Forget of unknown: Len = %d, want 0", r.Len())
	}
}

func TestRegistry_Concurrent(t *testing.T) {
	r := NewRegistry()
	const workers = 8
	const each = 100
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		w := w
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				name := mkName(w, i)
				r.MarkAttached(name)
				_ = r.IsAttached(name)
				_ = r.Len()
				_ = r.Snapshot()
			}
		}()
	}
	wg.Wait()
	if got, want := r.Len(), workers*each; got != want {
		t.Errorf("Len after concurrent fill = %d, want %d", got, want)
	}
}

func mkName(w, i int) string {
	const digits = "0123456789"
	out := make([]byte, 0, 8)
	out = append(out, 't', 'a', 'p', '-')
	out = appendInt(out, w)
	out = append(out, '-')
	out = appendInt(out, i)
	_ = digits
	return string(out)
}

func appendInt(b []byte, n int) []byte {
	if n == 0 {
		return append(b, '0')
	}
	var digits [10]byte
	i := len(digits)
	for n > 0 {
		i--
		digits[i] = '0' + byte(n%10)
		n /= 10
	}
	return append(b, digits[i:]...)
}
