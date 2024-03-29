// Code generated by mockery. DO NOT EDIT.

package github_team_reconciler

import (
	context "context"

	github "github.com/google/go-github/v50/github"
	mock "github.com/stretchr/testify/mock"
)

// MockTeamsService is an autogenerated mock type for the TeamsService type
type MockTeamsService struct {
	mock.Mock
}

type MockTeamsService_Expecter struct {
	mock *mock.Mock
}

func (_m *MockTeamsService) EXPECT() *MockTeamsService_Expecter {
	return &MockTeamsService_Expecter{mock: &_m.Mock}
}

// AddTeamMembershipBySlug provides a mock function with given fields: ctx, org, slug, user, opts
func (_m *MockTeamsService) AddTeamMembershipBySlug(ctx context.Context, org string, slug string, user string, opts *github.TeamAddTeamMembershipOptions) (*github.Membership, *github.Response, error) {
	ret := _m.Called(ctx, org, slug, user, opts)

	if len(ret) == 0 {
		panic("no return value specified for AddTeamMembershipBySlug")
	}

	var r0 *github.Membership
	var r1 *github.Response
	var r2 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, *github.TeamAddTeamMembershipOptions) (*github.Membership, *github.Response, error)); ok {
		return rf(ctx, org, slug, user, opts)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, *github.TeamAddTeamMembershipOptions) *github.Membership); ok {
		r0 = rf(ctx, org, slug, user, opts)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*github.Membership)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, string, *github.TeamAddTeamMembershipOptions) *github.Response); ok {
		r1 = rf(ctx, org, slug, user, opts)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*github.Response)
		}
	}

	if rf, ok := ret.Get(2).(func(context.Context, string, string, string, *github.TeamAddTeamMembershipOptions) error); ok {
		r2 = rf(ctx, org, slug, user, opts)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// MockTeamsService_AddTeamMembershipBySlug_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'AddTeamMembershipBySlug'
type MockTeamsService_AddTeamMembershipBySlug_Call struct {
	*mock.Call
}

// AddTeamMembershipBySlug is a helper method to define mock.On call
//   - ctx context.Context
//   - org string
//   - slug string
//   - user string
//   - opts *github.TeamAddTeamMembershipOptions
func (_e *MockTeamsService_Expecter) AddTeamMembershipBySlug(ctx interface{}, org interface{}, slug interface{}, user interface{}, opts interface{}) *MockTeamsService_AddTeamMembershipBySlug_Call {
	return &MockTeamsService_AddTeamMembershipBySlug_Call{Call: _e.mock.On("AddTeamMembershipBySlug", ctx, org, slug, user, opts)}
}

func (_c *MockTeamsService_AddTeamMembershipBySlug_Call) Run(run func(ctx context.Context, org string, slug string, user string, opts *github.TeamAddTeamMembershipOptions)) *MockTeamsService_AddTeamMembershipBySlug_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string), args[3].(string), args[4].(*github.TeamAddTeamMembershipOptions))
	})
	return _c
}

func (_c *MockTeamsService_AddTeamMembershipBySlug_Call) Return(_a0 *github.Membership, _a1 *github.Response, _a2 error) *MockTeamsService_AddTeamMembershipBySlug_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *MockTeamsService_AddTeamMembershipBySlug_Call) RunAndReturn(run func(context.Context, string, string, string, *github.TeamAddTeamMembershipOptions) (*github.Membership, *github.Response, error)) *MockTeamsService_AddTeamMembershipBySlug_Call {
	_c.Call.Return(run)
	return _c
}

// CreateOrUpdateIDPGroupConnectionsBySlug provides a mock function with given fields: ctx, org, team, opts
func (_m *MockTeamsService) CreateOrUpdateIDPGroupConnectionsBySlug(ctx context.Context, org string, team string, opts github.IDPGroupList) (*github.IDPGroupList, *github.Response, error) {
	ret := _m.Called(ctx, org, team, opts)

	if len(ret) == 0 {
		panic("no return value specified for CreateOrUpdateIDPGroupConnectionsBySlug")
	}

	var r0 *github.IDPGroupList
	var r1 *github.Response
	var r2 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, github.IDPGroupList) (*github.IDPGroupList, *github.Response, error)); ok {
		return rf(ctx, org, team, opts)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, github.IDPGroupList) *github.IDPGroupList); ok {
		r0 = rf(ctx, org, team, opts)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*github.IDPGroupList)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, github.IDPGroupList) *github.Response); ok {
		r1 = rf(ctx, org, team, opts)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*github.Response)
		}
	}

	if rf, ok := ret.Get(2).(func(context.Context, string, string, github.IDPGroupList) error); ok {
		r2 = rf(ctx, org, team, opts)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// MockTeamsService_CreateOrUpdateIDPGroupConnectionsBySlug_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CreateOrUpdateIDPGroupConnectionsBySlug'
type MockTeamsService_CreateOrUpdateIDPGroupConnectionsBySlug_Call struct {
	*mock.Call
}

// CreateOrUpdateIDPGroupConnectionsBySlug is a helper method to define mock.On call
//   - ctx context.Context
//   - org string
//   - team string
//   - opts github.IDPGroupList
func (_e *MockTeamsService_Expecter) CreateOrUpdateIDPGroupConnectionsBySlug(ctx interface{}, org interface{}, team interface{}, opts interface{}) *MockTeamsService_CreateOrUpdateIDPGroupConnectionsBySlug_Call {
	return &MockTeamsService_CreateOrUpdateIDPGroupConnectionsBySlug_Call{Call: _e.mock.On("CreateOrUpdateIDPGroupConnectionsBySlug", ctx, org, team, opts)}
}

func (_c *MockTeamsService_CreateOrUpdateIDPGroupConnectionsBySlug_Call) Run(run func(ctx context.Context, org string, team string, opts github.IDPGroupList)) *MockTeamsService_CreateOrUpdateIDPGroupConnectionsBySlug_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string), args[3].(github.IDPGroupList))
	})
	return _c
}

func (_c *MockTeamsService_CreateOrUpdateIDPGroupConnectionsBySlug_Call) Return(_a0 *github.IDPGroupList, _a1 *github.Response, _a2 error) *MockTeamsService_CreateOrUpdateIDPGroupConnectionsBySlug_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *MockTeamsService_CreateOrUpdateIDPGroupConnectionsBySlug_Call) RunAndReturn(run func(context.Context, string, string, github.IDPGroupList) (*github.IDPGroupList, *github.Response, error)) *MockTeamsService_CreateOrUpdateIDPGroupConnectionsBySlug_Call {
	_c.Call.Return(run)
	return _c
}

// CreateTeam provides a mock function with given fields: ctx, org, team
func (_m *MockTeamsService) CreateTeam(ctx context.Context, org string, team github.NewTeam) (*github.Team, *github.Response, error) {
	ret := _m.Called(ctx, org, team)

	if len(ret) == 0 {
		panic("no return value specified for CreateTeam")
	}

	var r0 *github.Team
	var r1 *github.Response
	var r2 error
	if rf, ok := ret.Get(0).(func(context.Context, string, github.NewTeam) (*github.Team, *github.Response, error)); ok {
		return rf(ctx, org, team)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, github.NewTeam) *github.Team); ok {
		r0 = rf(ctx, org, team)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*github.Team)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, github.NewTeam) *github.Response); ok {
		r1 = rf(ctx, org, team)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*github.Response)
		}
	}

	if rf, ok := ret.Get(2).(func(context.Context, string, github.NewTeam) error); ok {
		r2 = rf(ctx, org, team)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// MockTeamsService_CreateTeam_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CreateTeam'
type MockTeamsService_CreateTeam_Call struct {
	*mock.Call
}

// CreateTeam is a helper method to define mock.On call
//   - ctx context.Context
//   - org string
//   - team github.NewTeam
func (_e *MockTeamsService_Expecter) CreateTeam(ctx interface{}, org interface{}, team interface{}) *MockTeamsService_CreateTeam_Call {
	return &MockTeamsService_CreateTeam_Call{Call: _e.mock.On("CreateTeam", ctx, org, team)}
}

func (_c *MockTeamsService_CreateTeam_Call) Run(run func(ctx context.Context, org string, team github.NewTeam)) *MockTeamsService_CreateTeam_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(github.NewTeam))
	})
	return _c
}

func (_c *MockTeamsService_CreateTeam_Call) Return(_a0 *github.Team, _a1 *github.Response, _a2 error) *MockTeamsService_CreateTeam_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *MockTeamsService_CreateTeam_Call) RunAndReturn(run func(context.Context, string, github.NewTeam) (*github.Team, *github.Response, error)) *MockTeamsService_CreateTeam_Call {
	_c.Call.Return(run)
	return _c
}

// DeleteTeamBySlug provides a mock function with given fields: ctx, org, slug
func (_m *MockTeamsService) DeleteTeamBySlug(ctx context.Context, org string, slug string) (*github.Response, error) {
	ret := _m.Called(ctx, org, slug)

	if len(ret) == 0 {
		panic("no return value specified for DeleteTeamBySlug")
	}

	var r0 *github.Response
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) (*github.Response, error)); ok {
		return rf(ctx, org, slug)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string) *github.Response); ok {
		r0 = rf(ctx, org, slug)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*github.Response)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, org, slug)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockTeamsService_DeleteTeamBySlug_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'DeleteTeamBySlug'
type MockTeamsService_DeleteTeamBySlug_Call struct {
	*mock.Call
}

// DeleteTeamBySlug is a helper method to define mock.On call
//   - ctx context.Context
//   - org string
//   - slug string
func (_e *MockTeamsService_Expecter) DeleteTeamBySlug(ctx interface{}, org interface{}, slug interface{}) *MockTeamsService_DeleteTeamBySlug_Call {
	return &MockTeamsService_DeleteTeamBySlug_Call{Call: _e.mock.On("DeleteTeamBySlug", ctx, org, slug)}
}

func (_c *MockTeamsService_DeleteTeamBySlug_Call) Run(run func(ctx context.Context, org string, slug string)) *MockTeamsService_DeleteTeamBySlug_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string))
	})
	return _c
}

func (_c *MockTeamsService_DeleteTeamBySlug_Call) Return(_a0 *github.Response, _a1 error) *MockTeamsService_DeleteTeamBySlug_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockTeamsService_DeleteTeamBySlug_Call) RunAndReturn(run func(context.Context, string, string) (*github.Response, error)) *MockTeamsService_DeleteTeamBySlug_Call {
	_c.Call.Return(run)
	return _c
}

// EditTeamBySlug provides a mock function with given fields: ctx, org, slug, team, removeParent
func (_m *MockTeamsService) EditTeamBySlug(ctx context.Context, org string, slug string, team github.NewTeam, removeParent bool) (*github.Team, *github.Response, error) {
	ret := _m.Called(ctx, org, slug, team, removeParent)

	if len(ret) == 0 {
		panic("no return value specified for EditTeamBySlug")
	}

	var r0 *github.Team
	var r1 *github.Response
	var r2 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, github.NewTeam, bool) (*github.Team, *github.Response, error)); ok {
		return rf(ctx, org, slug, team, removeParent)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, github.NewTeam, bool) *github.Team); ok {
		r0 = rf(ctx, org, slug, team, removeParent)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*github.Team)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, github.NewTeam, bool) *github.Response); ok {
		r1 = rf(ctx, org, slug, team, removeParent)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*github.Response)
		}
	}

	if rf, ok := ret.Get(2).(func(context.Context, string, string, github.NewTeam, bool) error); ok {
		r2 = rf(ctx, org, slug, team, removeParent)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// MockTeamsService_EditTeamBySlug_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'EditTeamBySlug'
type MockTeamsService_EditTeamBySlug_Call struct {
	*mock.Call
}

// EditTeamBySlug is a helper method to define mock.On call
//   - ctx context.Context
//   - org string
//   - slug string
//   - team github.NewTeam
//   - removeParent bool
func (_e *MockTeamsService_Expecter) EditTeamBySlug(ctx interface{}, org interface{}, slug interface{}, team interface{}, removeParent interface{}) *MockTeamsService_EditTeamBySlug_Call {
	return &MockTeamsService_EditTeamBySlug_Call{Call: _e.mock.On("EditTeamBySlug", ctx, org, slug, team, removeParent)}
}

func (_c *MockTeamsService_EditTeamBySlug_Call) Run(run func(ctx context.Context, org string, slug string, team github.NewTeam, removeParent bool)) *MockTeamsService_EditTeamBySlug_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string), args[3].(github.NewTeam), args[4].(bool))
	})
	return _c
}

func (_c *MockTeamsService_EditTeamBySlug_Call) Return(_a0 *github.Team, _a1 *github.Response, _a2 error) *MockTeamsService_EditTeamBySlug_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *MockTeamsService_EditTeamBySlug_Call) RunAndReturn(run func(context.Context, string, string, github.NewTeam, bool) (*github.Team, *github.Response, error)) *MockTeamsService_EditTeamBySlug_Call {
	_c.Call.Return(run)
	return _c
}

// GetTeamBySlug provides a mock function with given fields: ctx, org, slug
func (_m *MockTeamsService) GetTeamBySlug(ctx context.Context, org string, slug string) (*github.Team, *github.Response, error) {
	ret := _m.Called(ctx, org, slug)

	if len(ret) == 0 {
		panic("no return value specified for GetTeamBySlug")
	}

	var r0 *github.Team
	var r1 *github.Response
	var r2 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) (*github.Team, *github.Response, error)); ok {
		return rf(ctx, org, slug)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string) *github.Team); ok {
		r0 = rf(ctx, org, slug)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*github.Team)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string) *github.Response); ok {
		r1 = rf(ctx, org, slug)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*github.Response)
		}
	}

	if rf, ok := ret.Get(2).(func(context.Context, string, string) error); ok {
		r2 = rf(ctx, org, slug)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// MockTeamsService_GetTeamBySlug_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetTeamBySlug'
type MockTeamsService_GetTeamBySlug_Call struct {
	*mock.Call
}

// GetTeamBySlug is a helper method to define mock.On call
//   - ctx context.Context
//   - org string
//   - slug string
func (_e *MockTeamsService_Expecter) GetTeamBySlug(ctx interface{}, org interface{}, slug interface{}) *MockTeamsService_GetTeamBySlug_Call {
	return &MockTeamsService_GetTeamBySlug_Call{Call: _e.mock.On("GetTeamBySlug", ctx, org, slug)}
}

func (_c *MockTeamsService_GetTeamBySlug_Call) Run(run func(ctx context.Context, org string, slug string)) *MockTeamsService_GetTeamBySlug_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string))
	})
	return _c
}

func (_c *MockTeamsService_GetTeamBySlug_Call) Return(_a0 *github.Team, _a1 *github.Response, _a2 error) *MockTeamsService_GetTeamBySlug_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *MockTeamsService_GetTeamBySlug_Call) RunAndReturn(run func(context.Context, string, string) (*github.Team, *github.Response, error)) *MockTeamsService_GetTeamBySlug_Call {
	_c.Call.Return(run)
	return _c
}

// ListTeamMembersBySlug provides a mock function with given fields: ctx, org, slug, opts
func (_m *MockTeamsService) ListTeamMembersBySlug(ctx context.Context, org string, slug string, opts *github.TeamListTeamMembersOptions) ([]*github.User, *github.Response, error) {
	ret := _m.Called(ctx, org, slug, opts)

	if len(ret) == 0 {
		panic("no return value specified for ListTeamMembersBySlug")
	}

	var r0 []*github.User
	var r1 *github.Response
	var r2 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, *github.TeamListTeamMembersOptions) ([]*github.User, *github.Response, error)); ok {
		return rf(ctx, org, slug, opts)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, *github.TeamListTeamMembersOptions) []*github.User); ok {
		r0 = rf(ctx, org, slug, opts)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*github.User)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, *github.TeamListTeamMembersOptions) *github.Response); ok {
		r1 = rf(ctx, org, slug, opts)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*github.Response)
		}
	}

	if rf, ok := ret.Get(2).(func(context.Context, string, string, *github.TeamListTeamMembersOptions) error); ok {
		r2 = rf(ctx, org, slug, opts)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// MockTeamsService_ListTeamMembersBySlug_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ListTeamMembersBySlug'
type MockTeamsService_ListTeamMembersBySlug_Call struct {
	*mock.Call
}

// ListTeamMembersBySlug is a helper method to define mock.On call
//   - ctx context.Context
//   - org string
//   - slug string
//   - opts *github.TeamListTeamMembersOptions
func (_e *MockTeamsService_Expecter) ListTeamMembersBySlug(ctx interface{}, org interface{}, slug interface{}, opts interface{}) *MockTeamsService_ListTeamMembersBySlug_Call {
	return &MockTeamsService_ListTeamMembersBySlug_Call{Call: _e.mock.On("ListTeamMembersBySlug", ctx, org, slug, opts)}
}

func (_c *MockTeamsService_ListTeamMembersBySlug_Call) Run(run func(ctx context.Context, org string, slug string, opts *github.TeamListTeamMembersOptions)) *MockTeamsService_ListTeamMembersBySlug_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string), args[3].(*github.TeamListTeamMembersOptions))
	})
	return _c
}

func (_c *MockTeamsService_ListTeamMembersBySlug_Call) Return(_a0 []*github.User, _a1 *github.Response, _a2 error) *MockTeamsService_ListTeamMembersBySlug_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *MockTeamsService_ListTeamMembersBySlug_Call) RunAndReturn(run func(context.Context, string, string, *github.TeamListTeamMembersOptions) ([]*github.User, *github.Response, error)) *MockTeamsService_ListTeamMembersBySlug_Call {
	_c.Call.Return(run)
	return _c
}

// ListTeamReposBySlug provides a mock function with given fields: ctx, org, slug, opts
func (_m *MockTeamsService) ListTeamReposBySlug(ctx context.Context, org string, slug string, opts *github.ListOptions) ([]*github.Repository, *github.Response, error) {
	ret := _m.Called(ctx, org, slug, opts)

	if len(ret) == 0 {
		panic("no return value specified for ListTeamReposBySlug")
	}

	var r0 []*github.Repository
	var r1 *github.Response
	var r2 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, *github.ListOptions) ([]*github.Repository, *github.Response, error)); ok {
		return rf(ctx, org, slug, opts)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, *github.ListOptions) []*github.Repository); ok {
		r0 = rf(ctx, org, slug, opts)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*github.Repository)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, *github.ListOptions) *github.Response); ok {
		r1 = rf(ctx, org, slug, opts)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*github.Response)
		}
	}

	if rf, ok := ret.Get(2).(func(context.Context, string, string, *github.ListOptions) error); ok {
		r2 = rf(ctx, org, slug, opts)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// MockTeamsService_ListTeamReposBySlug_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ListTeamReposBySlug'
type MockTeamsService_ListTeamReposBySlug_Call struct {
	*mock.Call
}

// ListTeamReposBySlug is a helper method to define mock.On call
//   - ctx context.Context
//   - org string
//   - slug string
//   - opts *github.ListOptions
func (_e *MockTeamsService_Expecter) ListTeamReposBySlug(ctx interface{}, org interface{}, slug interface{}, opts interface{}) *MockTeamsService_ListTeamReposBySlug_Call {
	return &MockTeamsService_ListTeamReposBySlug_Call{Call: _e.mock.On("ListTeamReposBySlug", ctx, org, slug, opts)}
}

func (_c *MockTeamsService_ListTeamReposBySlug_Call) Run(run func(ctx context.Context, org string, slug string, opts *github.ListOptions)) *MockTeamsService_ListTeamReposBySlug_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string), args[3].(*github.ListOptions))
	})
	return _c
}

func (_c *MockTeamsService_ListTeamReposBySlug_Call) Return(_a0 []*github.Repository, _a1 *github.Response, _a2 error) *MockTeamsService_ListTeamReposBySlug_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *MockTeamsService_ListTeamReposBySlug_Call) RunAndReturn(run func(context.Context, string, string, *github.ListOptions) ([]*github.Repository, *github.Response, error)) *MockTeamsService_ListTeamReposBySlug_Call {
	_c.Call.Return(run)
	return _c
}

// RemoveTeamMembershipBySlug provides a mock function with given fields: ctx, org, slug, user
func (_m *MockTeamsService) RemoveTeamMembershipBySlug(ctx context.Context, org string, slug string, user string) (*github.Response, error) {
	ret := _m.Called(ctx, org, slug, user)

	if len(ret) == 0 {
		panic("no return value specified for RemoveTeamMembershipBySlug")
	}

	var r0 *github.Response
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string) (*github.Response, error)); ok {
		return rf(ctx, org, slug, user)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string) *github.Response); ok {
		r0 = rf(ctx, org, slug, user)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*github.Response)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, string) error); ok {
		r1 = rf(ctx, org, slug, user)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockTeamsService_RemoveTeamMembershipBySlug_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RemoveTeamMembershipBySlug'
type MockTeamsService_RemoveTeamMembershipBySlug_Call struct {
	*mock.Call
}

// RemoveTeamMembershipBySlug is a helper method to define mock.On call
//   - ctx context.Context
//   - org string
//   - slug string
//   - user string
func (_e *MockTeamsService_Expecter) RemoveTeamMembershipBySlug(ctx interface{}, org interface{}, slug interface{}, user interface{}) *MockTeamsService_RemoveTeamMembershipBySlug_Call {
	return &MockTeamsService_RemoveTeamMembershipBySlug_Call{Call: _e.mock.On("RemoveTeamMembershipBySlug", ctx, org, slug, user)}
}

func (_c *MockTeamsService_RemoveTeamMembershipBySlug_Call) Run(run func(ctx context.Context, org string, slug string, user string)) *MockTeamsService_RemoveTeamMembershipBySlug_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string), args[3].(string))
	})
	return _c
}

func (_c *MockTeamsService_RemoveTeamMembershipBySlug_Call) Return(_a0 *github.Response, _a1 error) *MockTeamsService_RemoveTeamMembershipBySlug_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockTeamsService_RemoveTeamMembershipBySlug_Call) RunAndReturn(run func(context.Context, string, string, string) (*github.Response, error)) *MockTeamsService_RemoveTeamMembershipBySlug_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockTeamsService creates a new instance of MockTeamsService. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockTeamsService(t interface {
	mock.TestingT
	Cleanup(func())
},
) *MockTeamsService {
	mock := &MockTeamsService{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
