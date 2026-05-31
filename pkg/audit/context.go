package audit

import "context"

type factsKey struct{}

// WithFacts stores Facts in a context.
func WithFacts(ctx context.Context, facts *Facts) context.Context {
	return context.WithValue(ctx, factsKey{}, facts)
}

// GetFacts retrieves Facts from a context. Returns nil if not set.
func GetFacts(ctx context.Context) *Facts {
	f, _ := ctx.Value(factsKey{}).(*Facts)
	return f
}
