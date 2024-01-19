package main

import (
	"context"

	"github.com/nais/api-reconcilers/internal/cmd/reconciler"
)

func main() {
	ctx := context.Background()
	reconciler.Run(ctx)
}
