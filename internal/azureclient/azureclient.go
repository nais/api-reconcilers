package azureclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

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
	GetGroupByUniqueName(ctx context.Context, uniqueName string) (*GroupReference, error)
	GetOrCreateGroup(ctx context.Context, naisTeam *protoapi.Team, groupName string) (*Group, bool, error)
	GetUser(ctx context.Context, email string) (*Member, error)
	ListGroupMembers(ctx context.Context, grp *Group) ([]*Member, error)
	ListGroupOwners(ctx context.Context, grp *Group) ([]*Member, error)
	RemoveMemberFromGroup(ctx context.Context, grp *Group, member *Member) error
	DeleteGroup(ctx context.Context, grpID uuid.UUID) error
	UpsertGroupByUniqueName(ctx context.Context, uniqueName string, grp *Group) (*GroupReference, error)
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

	defer func() { _ = resp.Body.Close() }()

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
	defer func() { _ = resp.Body.Close() }()

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

func groupUniqueNameURL(uniqueName string) string {
	return "https://graph.microsoft.com/v1.0/groups(uniqueName='" + url.PathEscape(strings.ReplaceAll(uniqueName, "'", "''")) + "')"
}

// GetGroupByUniqueName returns nil only for a 404 response. Other errors must not be interpreted as permission to
// create a group.
func (s *client) GetGroupByUniqueName(ctx context.Context, uniqueName string) (*GroupReference, error) {
	u := groupUniqueNameURL(uniqueName) + "?" + url.Values{"$select": {"id"}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get Azure group with unique name %q: %s: %s", uniqueName, resp.Status, body)
	}
	group := &GroupReference{}
	if err := json.NewDecoder(resp.Body).Decode(group); err != nil {
		return nil, err
	}
	if group.ID == "" {
		return nil, fmt.Errorf("get Azure group with unique name %q: no ID returned", uniqueName)
	}
	return group, nil
}

// UpsertGroupByUniqueName uses Graph's alternate key to enforce uniqueness, even when a preceding read was stale or
// another reconciler creates the same parent.
func (s *client) UpsertGroupByUniqueName(ctx context.Context, uniqueName string, grp *Group) (*GroupReference, error) {
	payload, err := json.Marshal(grp)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, groupUniqueNameURL(uniqueName), bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Prefer", "create-if-missing")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusCreated:
		group := &GroupReference{}
		if err := json.NewDecoder(resp.Body).Decode(group); err != nil {
			return nil, err
		}
		if group.ID == "" {
			return nil, fmt.Errorf("upsert Azure group with unique name %q: no ID returned", uniqueName)
		}
		return group, nil
	case http.StatusNoContent:
		// Updating an existing group returns no body. A stale subsequent read
		// must cause a retry, never a fallback to an unkeyed POST /groups.
		group, err := s.GetGroupByUniqueName(ctx, uniqueName)
		if err != nil {
			return nil, err
		}
		if group == nil {
			return nil, fmt.Errorf("group with unique name %q is not yet visible after upsert; retry reconciliation", uniqueName)
		}
		return group, nil
	default:
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("upsert Azure group with unique name %q: %s: %s", uniqueName, resp.Status, body)
	}
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
	defer func() { _ = resp.Body.Close() }()

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
	return s.listGroupMembers(ctx, grp, "owners")
}

func (s *client) ListGroupMembers(ctx context.Context, grp *Group) ([]*Member, error) {
	return s.listGroupMembers(ctx, grp, "members")
}

func (s *client) listGroupMembers(ctx context.Context, grp *Group, relationship string) ([]*Member, error) {
	u := "https://graph.microsoft.com/v1.0/groups/" + grp.ID + "/" + relationship
	var members []*Member
	for u != "" {
		page, err := s.getGroupMembersPage(ctx, grp, relationship, u)
		if err != nil {
			return nil, err
		}
		members = append(members, page.Value...)
		u = page.NextLink
	}
	return members, nil
}

func (s *client) getGroupMembersPage(ctx context.Context, grp *Group, relationship, u string) (*MemberResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		text, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("list group %s %q: %s: %s", relationship, grp.MailNickname, resp.Status, string(text))
	}

	dec := json.NewDecoder(resp.Body)
	members := &MemberResponse{}
	err = dec.Decode(members)
	if err != nil {
		return nil, err
	}

	return members, nil
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
	defer func() { _ = resp.Body.Close() }()

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
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent {
		text, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("remove member %q from azure group %q: %s: %s", member.Mail, grp.MailNickname, resp.Status, string(text))
	}

	return nil
}

func (s *client) DeleteGroup(ctx context.Context, grpID uuid.UUID) error {
	u := "https://graph.microsoft.com/v1.0/groups/" + grpID.String()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u, nil)
	if err != nil {
		return err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil
	}

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("remove azure group with ID: %q: %q: %q", grpID, resp.Status, string(body))
	}

	return nil
}
