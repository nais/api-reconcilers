package reconcilers_test

import (
	"testing"

	"github.com/nais/api-reconcilers/internal/reconcilers"
)

func TestInFlight(t *testing.T) {
	const (
		team1 = "team-1"
		team2 = "team-2"
	)
	inFlight := reconcilers.NewInFlight()

	if !inFlight.Set(team1) {
		t.Errorf("Expected Set to return true")
	}

	if !inFlight.Set(team2) {
		t.Errorf("Expected Set to return true")
	}

	if inFlight.Set(team1) {
		t.Errorf("Expected Set to return false")
	}

	if inFlight.Set(team2) {
		t.Errorf("Expected Set to return false")
	}

	inFlight.Remove(team1)

	if !inFlight.Set(team1) {
		t.Errorf("Expected Set to return true")
	}

	if inFlight.Set(team2) {
		t.Errorf("Expected Set to return false")
	}
}
