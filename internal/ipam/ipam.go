// Package ipam allocates client addresses from per-protocol pools.
package ipam

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
)

// ErrExhausted is returned when a pool has no free address.
var ErrExhausted = errors.New("address pool exhausted")

// Pool hands out host addresses of a prefix. The network address, the
// first host (used by the VPN server itself) and the broadcast address are
// never allocated.
type Pool struct {
	mu     sync.Mutex
	prefix netip.Prefix
	used   map[netip.Addr]string
	next   netip.Addr
}

// NewPool creates a pool.
func NewPool(p netip.Prefix) *Pool {
	p = p.Masked()
	return &Pool{prefix: p, used: map[netip.Addr]string{}, next: p.Addr().Next().Next()}
}

// Prefix returns the pool prefix.
func (p *Pool) Prefix() netip.Prefix { return p.prefix }

// Gateway returns the server-side address of the pool.
func (p *Pool) Gateway() netip.Addr { return p.prefix.Addr().Next() }

// Size returns the number of allocatable addresses.
func (p *Pool) Size() int { return (1 << (32 - p.prefix.Bits())) - 3 }

// Used returns the number of allocated addresses.
func (p *Pool) Used() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.used)
}

func (p *Pool) valid(a netip.Addr) bool {
	if !p.prefix.Contains(a) {
		return false
	}
	first := p.prefix.Addr()
	if a == first || a == first.Next() {
		return false
	}
	last := lastAddr(p.prefix)
	return a != last
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().As4()
	host := uint32(1)<<(32-p.Bits()) - 1
	v := (uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])) | host
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// Allocate returns a free address tagged with owner. Addresses are handed
// out round-robin so a released address is not immediately reused.
func (p *Pool) Allocate(owner string) (netip.Addr, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.used) >= p.Size() {
		return netip.Addr{}, ErrExhausted
	}
	a := p.next
	for i := 0; i < p.Size()+3; i++ {
		if !p.valid(a) {
			a = p.prefix.Addr().Next().Next()
		}
		if _, taken := p.used[a]; !taken {
			p.used[a] = owner
			p.next = a.Next()
			return a, nil
		}
		a = a.Next()
	}
	return netip.Addr{}, ErrExhausted
}

// Reserve marks a specific address as used (e.g. on restart recovery).
func (p *Pool) Reserve(a netip.Addr, owner string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.valid(a) {
		return fmt.Errorf("%s is not in pool %s", a, p.prefix)
	}
	if o, taken := p.used[a]; taken && o != owner {
		return fmt.Errorf("%s already used by %s", a, o)
	}
	p.used[a] = owner
	return nil
}

// Release frees an address.
func (p *Pool) Release(a netip.Addr) {
	p.mu.Lock()
	delete(p.used, a)
	p.mu.Unlock()
}

// Owner returns who holds an address.
func (p *Pool) Owner(a netip.Addr) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	o, ok := p.used[a]
	return o, ok
}

// IPAM groups the pools of all protocols.
type IPAM struct {
	pools map[string]*Pool
}

// New creates pools for the given protocol prefixes.
func New(prefixes map[string]netip.Prefix) *IPAM {
	m := &IPAM{pools: map[string]*Pool{}}
	for proto, p := range prefixes {
		m.pools[proto] = NewPool(p)
	}
	return m
}

// Pool returns the pool of a protocol.
func (m *IPAM) Pool(proto string) *Pool { return m.pools[proto] }

// Pools returns all pools.
func (m *IPAM) Pools() map[string]*Pool { return m.pools }

// ProtocolOf returns the protocol whose pool contains a.
func (m *IPAM) ProtocolOf(a netip.Addr) (string, bool) {
	for proto, p := range m.pools {
		if p.prefix.Contains(a) {
			return proto, true
		}
	}
	return "", false
}

// Prefixes returns all pool prefixes.
func (m *IPAM) Prefixes() []netip.Prefix {
	var out []netip.Prefix
	for _, p := range m.pools {
		out = append(out, p.prefix)
	}
	return out
}
