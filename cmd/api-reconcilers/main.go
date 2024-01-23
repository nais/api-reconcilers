package main

import (
	"context"

	"github.com/nais/api-reconcilers/internal/cmd/reconciler"
)

func main() {
	reconciler.Run(context.Background())
}
