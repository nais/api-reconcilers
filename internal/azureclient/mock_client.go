// Code generated by mockery. DO NOT EDIT.

package azureclient

import (
	context "context"

	protoapi "github.com/nais/api/pkg/apiclient/protoapi"
	mock "github.com/stretchr/testify/mock"

	uuid "github.com/google/uuid"
)

// MockClient is an autogenerated mock type for the Client type
type MockClient struct {
	mock.Mock
}

type MockClient_Expecter struct {
	mock *mock.Mock
}

func (_m *MockClient) EXPECT() *MockClient_Expecter {
	return &MockClient_Expecter{mock: &_m.Mock}
}

// AddMemberToGroup provides a mock function with given fields: ctx, grp, member
func (_m *MockClient) AddMemberToGroup(ctx context.Context, grp *Group, member *Member) error {
	ret := _m.Called(ctx, grp, member)

	if len(ret) == 0 {
		panic("no return value specified for AddMemberToGroup")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *Group, *Member) error); ok {
		r0 = rf(ctx, grp, member)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockClient_AddMemberToGroup_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'AddMemberToGroup'
type MockClient_AddMemberToGroup_Call struct {
	*mock.Call
}

// AddMemberToGroup is a helper method to define mock.On call
//   - ctx context.Context
//   - grp *Group
//   - member *Member
func (_e *MockClient_Expecter) AddMemberToGroup(ctx interface{}, grp interface{}, member interface{}) *MockClient_AddMemberToGroup_Call {
	return &MockClient_AddMemberToGroup_Call{Call: _e.mock.On("AddMemberToGroup", ctx, grp, member)}
}

func (_c *MockClient_AddMemberToGroup_Call) Run(run func(ctx context.Context, grp *Group, member *Member)) *MockClient_AddMemberToGroup_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*Group), args[2].(*Member))
	})
	return _c
}

func (_c *MockClient_AddMemberToGroup_Call) Return(_a0 error) *MockClient_AddMemberToGroup_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockClient_AddMemberToGroup_Call) RunAndReturn(run func(context.Context, *Group, *Member) error) *MockClient_AddMemberToGroup_Call {
	_c.Call.Return(run)
	return _c
}

// CreateGroup provides a mock function with given fields: ctx, grp
func (_m *MockClient) CreateGroup(ctx context.Context, grp *Group) (*Group, error) {
	ret := _m.Called(ctx, grp)

	if len(ret) == 0 {
		panic("no return value specified for CreateGroup")
	}

	var r0 *Group
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *Group) (*Group, error)); ok {
		return rf(ctx, grp)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *Group) *Group); ok {
		r0 = rf(ctx, grp)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*Group)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *Group) error); ok {
		r1 = rf(ctx, grp)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockClient_CreateGroup_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CreateGroup'
type MockClient_CreateGroup_Call struct {
	*mock.Call
}

// CreateGroup is a helper method to define mock.On call
//   - ctx context.Context
//   - grp *Group
func (_e *MockClient_Expecter) CreateGroup(ctx interface{}, grp interface{}) *MockClient_CreateGroup_Call {
	return &MockClient_CreateGroup_Call{Call: _e.mock.On("CreateGroup", ctx, grp)}
}

func (_c *MockClient_CreateGroup_Call) Run(run func(ctx context.Context, grp *Group)) *MockClient_CreateGroup_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*Group))
	})
	return _c
}

func (_c *MockClient_CreateGroup_Call) Return(_a0 *Group, _a1 error) *MockClient_CreateGroup_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockClient_CreateGroup_Call) RunAndReturn(run func(context.Context, *Group) (*Group, error)) *MockClient_CreateGroup_Call {
	_c.Call.Return(run)
	return _c
}

// DeleteGroup provides a mock function with given fields: ctx, grpID
func (_m *MockClient) DeleteGroup(ctx context.Context, grpID uuid.UUID) error {
	ret := _m.Called(ctx, grpID)

	if len(ret) == 0 {
		panic("no return value specified for DeleteGroup")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID) error); ok {
		r0 = rf(ctx, grpID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockClient_DeleteGroup_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'DeleteGroup'
type MockClient_DeleteGroup_Call struct {
	*mock.Call
}

// DeleteGroup is a helper method to define mock.On call
//   - ctx context.Context
//   - grpID uuid.UUID
func (_e *MockClient_Expecter) DeleteGroup(ctx interface{}, grpID interface{}) *MockClient_DeleteGroup_Call {
	return &MockClient_DeleteGroup_Call{Call: _e.mock.On("DeleteGroup", ctx, grpID)}
}

func (_c *MockClient_DeleteGroup_Call) Run(run func(ctx context.Context, grpID uuid.UUID)) *MockClient_DeleteGroup_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(uuid.UUID))
	})
	return _c
}

func (_c *MockClient_DeleteGroup_Call) Return(_a0 error) *MockClient_DeleteGroup_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockClient_DeleteGroup_Call) RunAndReturn(run func(context.Context, uuid.UUID) error) *MockClient_DeleteGroup_Call {
	_c.Call.Return(run)
	return _c
}

// GetGroupById provides a mock function with given fields: ctx, id
func (_m *MockClient) GetGroupById(ctx context.Context, id uuid.UUID) (*Group, error) {
	ret := _m.Called(ctx, id)

	if len(ret) == 0 {
		panic("no return value specified for GetGroupById")
	}

	var r0 *Group
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID) (*Group, error)); ok {
		return rf(ctx, id)
	}
	if rf, ok := ret.Get(0).(func(context.Context, uuid.UUID) *Group); ok {
		r0 = rf(ctx, id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*Group)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, uuid.UUID) error); ok {
		r1 = rf(ctx, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockClient_GetGroupById_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetGroupById'
type MockClient_GetGroupById_Call struct {
	*mock.Call
}

// GetGroupById is a helper method to define mock.On call
//   - ctx context.Context
//   - id uuid.UUID
func (_e *MockClient_Expecter) GetGroupById(ctx interface{}, id interface{}) *MockClient_GetGroupById_Call {
	return &MockClient_GetGroupById_Call{Call: _e.mock.On("GetGroupById", ctx, id)}
}

func (_c *MockClient_GetGroupById_Call) Run(run func(ctx context.Context, id uuid.UUID)) *MockClient_GetGroupById_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(uuid.UUID))
	})
	return _c
}

func (_c *MockClient_GetGroupById_Call) Return(_a0 *Group, _a1 error) *MockClient_GetGroupById_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockClient_GetGroupById_Call) RunAndReturn(run func(context.Context, uuid.UUID) (*Group, error)) *MockClient_GetGroupById_Call {
	_c.Call.Return(run)
	return _c
}

// GetOrCreateGroup provides a mock function with given fields: ctx, naisTeam, groupName
func (_m *MockClient) GetOrCreateGroup(ctx context.Context, naisTeam *protoapi.Team, groupName string) (*Group, bool, error) {
	ret := _m.Called(ctx, naisTeam, groupName)

	if len(ret) == 0 {
		panic("no return value specified for GetOrCreateGroup")
	}

	var r0 *Group
	var r1 bool
	var r2 error
	if rf, ok := ret.Get(0).(func(context.Context, *protoapi.Team, string) (*Group, bool, error)); ok {
		return rf(ctx, naisTeam, groupName)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *protoapi.Team, string) *Group); ok {
		r0 = rf(ctx, naisTeam, groupName)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*Group)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *protoapi.Team, string) bool); ok {
		r1 = rf(ctx, naisTeam, groupName)
	} else {
		r1 = ret.Get(1).(bool)
	}

	if rf, ok := ret.Get(2).(func(context.Context, *protoapi.Team, string) error); ok {
		r2 = rf(ctx, naisTeam, groupName)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// MockClient_GetOrCreateGroup_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetOrCreateGroup'
type MockClient_GetOrCreateGroup_Call struct {
	*mock.Call
}

// GetOrCreateGroup is a helper method to define mock.On call
//   - ctx context.Context
//   - naisTeam *protoapi.Team
//   - groupName string
func (_e *MockClient_Expecter) GetOrCreateGroup(ctx interface{}, naisTeam interface{}, groupName interface{}) *MockClient_GetOrCreateGroup_Call {
	return &MockClient_GetOrCreateGroup_Call{Call: _e.mock.On("GetOrCreateGroup", ctx, naisTeam, groupName)}
}

func (_c *MockClient_GetOrCreateGroup_Call) Run(run func(ctx context.Context, naisTeam *protoapi.Team, groupName string)) *MockClient_GetOrCreateGroup_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*protoapi.Team), args[2].(string))
	})
	return _c
}

func (_c *MockClient_GetOrCreateGroup_Call) Return(_a0 *Group, _a1 bool, _a2 error) *MockClient_GetOrCreateGroup_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *MockClient_GetOrCreateGroup_Call) RunAndReturn(run func(context.Context, *protoapi.Team, string) (*Group, bool, error)) *MockClient_GetOrCreateGroup_Call {
	_c.Call.Return(run)
	return _c
}

// GetUser provides a mock function with given fields: ctx, email
func (_m *MockClient) GetUser(ctx context.Context, email string) (*Member, error) {
	ret := _m.Called(ctx, email)

	if len(ret) == 0 {
		panic("no return value specified for GetUser")
	}

	var r0 *Member
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (*Member, error)); ok {
		return rf(ctx, email)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) *Member); ok {
		r0 = rf(ctx, email)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*Member)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, email)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockClient_GetUser_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetUser'
type MockClient_GetUser_Call struct {
	*mock.Call
}

// GetUser is a helper method to define mock.On call
//   - ctx context.Context
//   - email string
func (_e *MockClient_Expecter) GetUser(ctx interface{}, email interface{}) *MockClient_GetUser_Call {
	return &MockClient_GetUser_Call{Call: _e.mock.On("GetUser", ctx, email)}
}

func (_c *MockClient_GetUser_Call) Run(run func(ctx context.Context, email string)) *MockClient_GetUser_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string))
	})
	return _c
}

func (_c *MockClient_GetUser_Call) Return(_a0 *Member, _a1 error) *MockClient_GetUser_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockClient_GetUser_Call) RunAndReturn(run func(context.Context, string) (*Member, error)) *MockClient_GetUser_Call {
	_c.Call.Return(run)
	return _c
}

// ListGroupMembers provides a mock function with given fields: ctx, grp
func (_m *MockClient) ListGroupMembers(ctx context.Context, grp *Group) ([]*Member, error) {
	ret := _m.Called(ctx, grp)

	if len(ret) == 0 {
		panic("no return value specified for ListGroupMembers")
	}

	var r0 []*Member
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *Group) ([]*Member, error)); ok {
		return rf(ctx, grp)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *Group) []*Member); ok {
		r0 = rf(ctx, grp)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*Member)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *Group) error); ok {
		r1 = rf(ctx, grp)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockClient_ListGroupMembers_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ListGroupMembers'
type MockClient_ListGroupMembers_Call struct {
	*mock.Call
}

// ListGroupMembers is a helper method to define mock.On call
//   - ctx context.Context
//   - grp *Group
func (_e *MockClient_Expecter) ListGroupMembers(ctx interface{}, grp interface{}) *MockClient_ListGroupMembers_Call {
	return &MockClient_ListGroupMembers_Call{Call: _e.mock.On("ListGroupMembers", ctx, grp)}
}

func (_c *MockClient_ListGroupMembers_Call) Run(run func(ctx context.Context, grp *Group)) *MockClient_ListGroupMembers_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*Group))
	})
	return _c
}

func (_c *MockClient_ListGroupMembers_Call) Return(_a0 []*Member, _a1 error) *MockClient_ListGroupMembers_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockClient_ListGroupMembers_Call) RunAndReturn(run func(context.Context, *Group) ([]*Member, error)) *MockClient_ListGroupMembers_Call {
	_c.Call.Return(run)
	return _c
}

// ListGroupOwners provides a mock function with given fields: ctx, grp
func (_m *MockClient) ListGroupOwners(ctx context.Context, grp *Group) ([]*Member, error) {
	ret := _m.Called(ctx, grp)

	if len(ret) == 0 {
		panic("no return value specified for ListGroupOwners")
	}

	var r0 []*Member
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *Group) ([]*Member, error)); ok {
		return rf(ctx, grp)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *Group) []*Member); ok {
		r0 = rf(ctx, grp)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*Member)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *Group) error); ok {
		r1 = rf(ctx, grp)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockClient_ListGroupOwners_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ListGroupOwners'
type MockClient_ListGroupOwners_Call struct {
	*mock.Call
}

// ListGroupOwners is a helper method to define mock.On call
//   - ctx context.Context
//   - grp *Group
func (_e *MockClient_Expecter) ListGroupOwners(ctx interface{}, grp interface{}) *MockClient_ListGroupOwners_Call {
	return &MockClient_ListGroupOwners_Call{Call: _e.mock.On("ListGroupOwners", ctx, grp)}
}

func (_c *MockClient_ListGroupOwners_Call) Run(run func(ctx context.Context, grp *Group)) *MockClient_ListGroupOwners_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*Group))
	})
	return _c
}

func (_c *MockClient_ListGroupOwners_Call) Return(_a0 []*Member, _a1 error) *MockClient_ListGroupOwners_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockClient_ListGroupOwners_Call) RunAndReturn(run func(context.Context, *Group) ([]*Member, error)) *MockClient_ListGroupOwners_Call {
	_c.Call.Return(run)
	return _c
}

// RemoveMemberFromGroup provides a mock function with given fields: ctx, grp, member
func (_m *MockClient) RemoveMemberFromGroup(ctx context.Context, grp *Group, member *Member) error {
	ret := _m.Called(ctx, grp, member)

	if len(ret) == 0 {
		panic("no return value specified for RemoveMemberFromGroup")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *Group, *Member) error); ok {
		r0 = rf(ctx, grp, member)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockClient_RemoveMemberFromGroup_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RemoveMemberFromGroup'
type MockClient_RemoveMemberFromGroup_Call struct {
	*mock.Call
}

// RemoveMemberFromGroup is a helper method to define mock.On call
//   - ctx context.Context
//   - grp *Group
//   - member *Member
func (_e *MockClient_Expecter) RemoveMemberFromGroup(ctx interface{}, grp interface{}, member interface{}) *MockClient_RemoveMemberFromGroup_Call {
	return &MockClient_RemoveMemberFromGroup_Call{Call: _e.mock.On("RemoveMemberFromGroup", ctx, grp, member)}
}

func (_c *MockClient_RemoveMemberFromGroup_Call) Run(run func(ctx context.Context, grp *Group, member *Member)) *MockClient_RemoveMemberFromGroup_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*Group), args[2].(*Member))
	})
	return _c
}

func (_c *MockClient_RemoveMemberFromGroup_Call) Return(_a0 error) *MockClient_RemoveMemberFromGroup_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockClient_RemoveMemberFromGroup_Call) RunAndReturn(run func(context.Context, *Group, *Member) error) *MockClient_RemoveMemberFromGroup_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockClient creates a new instance of MockClient. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockClient(t interface {
	mock.TestingT
	Cleanup(func())
},
) *MockClient {
	mock := &MockClient{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
