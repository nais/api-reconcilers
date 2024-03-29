package reconcilers

import "sync"

type InFlight interface {
	Set(teamSlug string) bool
	Remove(teamSlug string)
}

type inFlight struct {
	teamsLock sync.Mutex
	teams     map[string]struct{}
}

func NewInFlight() InFlight {
	return &inFlight{
		teams: make(map[string]struct{}),
	}
}

func (i *inFlight) Set(teamSlug string) bool {
	i.teamsLock.Lock()
	defer i.teamsLock.Unlock()

	if _, inFlight := i.teams[teamSlug]; !inFlight {
		i.teams[teamSlug] = struct{}{}
		return true
	}
	return false
}

func (i *inFlight) Remove(teamSlug string) {
	i.teamsLock.Lock()
	defer i.teamsLock.Unlock()

	delete(i.teams, teamSlug)
}
