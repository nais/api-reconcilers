package azureclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/google/uuid"
	"github.com/nais/api/pkg/apiclient/protoapi"
)

type client struct {
	client *http.Client
}

type Client interface {
	AddMemberToGroup(ctx context.Context, grp *Group, member *Member) error
	CreateGroup(ctx context.Context, grp *Group) (*Group, error)
	GetGroupById(ctx context.Context, id uuid.UUID) (*Group, error)
	GetOrCreateGroup(ctx context.Context, naisTeam *protoapi.Team, groupName string) (*Group, bool, error)
	GetUser(ctx context.Context, email string) (*Member, error)
	ListGroupMembers(ctx context.Context, grp *Group) ([]*Member, error)
	ListGroupOwners(ctx context.Context, grp *Group) ([]*Member, error)
	RemoveMemberFromGroup(ctx context.Context, grp *Group, member *Member) error
	DeleteGroup(ctx context.Context, grpID uuid.UUID) error
}

func New(c *http.Client) Client {
	return &client{
		client: c,
	}
}

func (s *client) GetUser(ctx context.Context, email string) (*Member, error) {
	u := "https://graph.microsoft.com/v1.0/users/" + email

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		text, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%s: %s", resp.Status, string(text))
	}

	dec := json.NewDecoder(resp.Body)
	user := &Member{}
	err = dec.Decode(user)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (s *client) GetGroupById(ctx context.Context, id uuid.UUID) (*Group, error) {
	u := "https://graph.microsoft.com/v1.0/groups/" + id.String()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("azure group with ID %q does not exist", id.String())
	}

	dec := json.NewDecoder(resp.Body)
	grp := &Group{}
	err = dec.Decode(grp)
	if err != nil {
		return nil, err
	}

	return grp, nil
}

func (s *client) CreateGroup(ctx context.Context, grp *Group) (*Group, error) {
	u := "https://graph.microsoft.com/v1.0/groups"

	payload, err := json.Marshal(grp)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		text, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("create azure group %q: %s: %s", grp.MailNickname, resp.Status, string(text))
	}

	dec := json.NewDecoder(resp.Body)
	grp = &Group{}
	err = dec.Decode(grp)
	if err != nil {
		return nil, err
	}

	if len(grp.ID) == 0 {
		return nil, fmt.Errorf("azure group %q created, but no ID returned", grp.MailNickname)
	}

	return grp, nil
}

// GetOrCreateGroup Get or create a group from the Graph API. The second return value informs if the group was
// created or not.
func (s *client) GetOrCreateGroup(ctx context.Context, naisTeam *protoapi.Team, groupName string) (*Group, bool, error) {
	if naisTeam.EntraIdGroupId != nil {
		existingGroupID, err := uuid.Parse(*naisTeam.EntraIdGroupId)
		if err != nil {
			return nil, false, fmt.Errorf("group ID %q is not a valid UUID: %w", *naisTeam.EntraIdGroupId, err)
		}

		grp, err := s.GetGroupById(ctx, existingGroupID)
		return grp, false, err
	}

	createdGroup, err := s.CreateGroup(ctx, &Group{
		Description:     naisTeam.Purpose,
		DisplayName:     groupName,
		GroupTypes:      nil,
		MailEnabled:     false,
		MailNickname:    groupName,
		SecurityEnabled: true,
	})
	if err != nil {
		return nil, false, err
	}
	return createdGroup, true, nil
}

func (s *client) ListGroupOwners(ctx context.Context, grp *Group) ([]*Member, error) {
	u := "https://graph.microsoft.com/v1.0/groups/" + grp.ID + "/owners"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		text, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("list group owners %q: %s: %s", grp.MailNickname, resp.Status, string(text))
	}

	defer resp.Body.Close()
	dec := json.NewDecoder(resp.Body)
	owners := &MemberResponse{}
	err = dec.Decode(owners)
	if err != nil {
		return nil, err
	}

	return owners.Value, nil
}

func (s *client) ListGroupMembers(ctx context.Context, grp *Group) ([]*Member, error) {
	u := "https://graph.microsoft.com/v1.0/groups/" + grp.ID + "/members"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		text, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("list group members %q: %s: %s", grp.MailNickname, resp.Status, string(text))
	}

	defer resp.Body.Close()
	dec := json.NewDecoder(resp.Body)
	members := &MemberResponse{}
	err = dec.Decode(members)
	if err != nil {
		return nil, err
	}

	return members.Value, nil
}

func (s *client) AddMemberToGroup(ctx context.Context, grp *Group, member *Member) error {
	u := "https://graph.microsoft.com/v1.0/groups/" + grp.ID + "/members/$ref"

	request := &AddMemberRequest{
		ODataID: member.ODataID(),
	}

	payload, err := json.Marshal(request)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		text, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("add member %q to azure group %q: %s: %s", member.Mail, grp.MailNickname, resp.Status, string(text))
	}

	return nil
}

func (s *client) RemoveMemberFromGroup(ctx context.Context, grp *Group, member *Member) error {
	u := "https://graph.microsoft.com/v1.0/groups/" + grp.ID + "/members/" + member.ID + "/$ref"

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u, nil)
	if err != nil {
		return err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		text, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("remove member %q from azure group %q: %s: %s", member.Mail, grp.MailNickname, resp.Status, string(text))
	}

	return nil
}

func (s *client) DeleteGroup(ctx context.Context, grpID uuid.UUID) error {
	url := "https://graph.microsoft.com/v1.0/groups/" + grpID.String()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil
	}

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("remove azure group with ID: %q: %q: %q", grpID, resp.Status, string(body))
	}

	return nil
}
