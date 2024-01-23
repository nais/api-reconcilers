// Code generated by mockery. DO NOT EDIT.

package github_team_reconciler

import (
	context "context"

	mock "github.com/stretchr/testify/mock"
)

// MockGraphClient is an autogenerated mock type for the GraphClient type
type MockGraphClient struct {
	mock.Mock
}

type MockGraphClient_Expecter struct {
	mock *mock.Mock
}

func (_m *MockGraphClient) EXPECT() *MockGraphClient_Expecter {
	return &MockGraphClient_Expecter{mock: &_m.Mock}
}

// Query provides a mock function with given fields: ctx, q, variables
func (_m *MockGraphClient) Query(ctx context.Context, q interface{}, variables map[string]interface{}) error {
	ret := _m.Called(ctx, q, variables)

	if len(ret) == 0 {
		panic("no return value specified for Query")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, interface{}, map[string]interface{}) error); ok {
		r0 = rf(ctx, q, variables)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockGraphClient_Query_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Query'
type MockGraphClient_Query_Call struct {
	*mock.Call
}

// Query is a helper method to define mock.On call
//   - ctx context.Context
//   - q interface{}
//   - variables map[string]interface{}
func (_e *MockGraphClient_Expecter) Query(ctx interface{}, q interface{}, variables interface{}) *MockGraphClient_Query_Call {
	return &MockGraphClient_Query_Call{Call: _e.mock.On("Query", ctx, q, variables)}
}

func (_c *MockGraphClient_Query_Call) Run(run func(ctx context.Context, q interface{}, variables map[string]interface{})) *MockGraphClient_Query_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(interface{}), args[2].(map[string]interface{}))
	})
	return _c
}

func (_c *MockGraphClient_Query_Call) Return(_a0 error) *MockGraphClient_Query_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockGraphClient_Query_Call) RunAndReturn(run func(context.Context, interface{}, map[string]interface{}) error) *MockGraphClient_Query_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockGraphClient creates a new instance of MockGraphClient. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockGraphClient(t interface {
	mock.TestingT
	Cleanup(func())
},
) *MockGraphClient {
	mock := &MockGraphClient{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
