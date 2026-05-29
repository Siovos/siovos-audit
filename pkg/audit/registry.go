package audit

// Registry holds all available checks and supports filtering by ID.
type Registry struct {
	checks []Check
	byID   map[string]Check
}

func NewRegistry() *Registry {
	return &Registry{
		byID: make(map[string]Check),
	}
}

func (r *Registry) Register(c Check) {
	if _, exists := r.byID[c.ID()]; exists {
		return
	}
	r.checks = append(r.checks, c)
	r.byID[c.ID()] = c
}

func (r *Registry) Get(id string) (Check, bool) {
	c, ok := r.byID[id]
	return c, ok
}

func (r *Registry) All() []Check {
	return r.checks
}

func (r *Registry) Filter(ids []string) []Check {
	if len(ids) == 0 {
		return r.checks
	}
	var filtered []Check
	for _, id := range ids {
		if c, ok := r.byID[id]; ok {
			filtered = append(filtered, c)
		}
	}
	return filtered
}
