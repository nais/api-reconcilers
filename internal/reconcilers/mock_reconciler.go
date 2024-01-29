// Code generated by mockery. DO NOT EDIT.

package reconcilers

import (
	context "context"

	apiclient "github.com/nais/api/pkg/apiclient"

	logrus "github.com/sirupsen/logrus"

	mock "github.com/stretchr/testify/mock"

	protoapi "github.com/nais/api/pkg/protoapi"
)

// MockReconciler is an autogenerated mock type for the Reconciler type
type MockReconciler struct {
	mock.Mock
}

type MockReconciler_Expecter struct {
	mock *mock.Mock
}

func (_m *MockReconciler) EXPECT() *MockReconciler_Expecter {
	return &MockReconciler_Expecter{mock: &_m.Mock}
}

// Configuration provides a mock function with given fields:
func (_m *MockReconciler) Configuration() *protoapi.NewReconciler {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Configuration")
	}

	var r0 *protoapi.NewReconciler
	if rf, ok := ret.Get(0).(func() *protoapi.NewReconciler); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*protoapi.NewReconciler)
		}
	}

	return r0
}

// MockReconciler_Configuration_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Configuration'
type MockReconciler_Configuration_Call struct {
	*mock.Call
}

// Configuration is a helper method to define mock.On call
func (_e *MockReconciler_Expecter) Configuration() *MockReconciler_Configuration_Call {
	return &MockReconciler_Configuration_Call{Call: _e.mock.On("Configuration")}
}

func (_c *MockReconciler_Configuration_Call) Run(run func()) *MockReconciler_Configuration_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockReconciler_Configuration_Call) Return(_a0 *protoapi.NewReconciler) *MockReconciler_Configuration_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockReconciler_Configuration_Call) RunAndReturn(run func() *protoapi.NewReconciler) *MockReconciler_Configuration_Call {
	_c.Call.Return(run)
	return _c
}

// Delete provides a mock function with given fields: ctx, client, naisTeam, log
func (_m *MockReconciler) Delete(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {
	ret := _m.Called(ctx, client, naisTeam, log)

	if len(ret) == 0 {
		panic("no return value specified for Delete")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *apiclient.APIClient, *protoapi.Team, logrus.FieldLogger) error); ok {
		r0 = rf(ctx, client, naisTeam, log)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockReconciler_Delete_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Delete'
type MockReconciler_Delete_Call struct {
	*mock.Call
}

// Delete is a helper method to define mock.On call
//   - ctx context.Context
//   - client *apiclient.APIClient
//   - naisTeam *protoapi.Team
//   - log logrus.FieldLogger
func (_e *MockReconciler_Expecter) Delete(ctx interface{}, client interface{}, naisTeam interface{}, log interface{}) *MockReconciler_Delete_Call {
	return &MockReconciler_Delete_Call{Call: _e.mock.On("Delete", ctx, client, naisTeam, log)}
}

func (_c *MockReconciler_Delete_Call) Run(run func(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger)) *MockReconciler_Delete_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*apiclient.APIClient), args[2].(*protoapi.Team), args[3].(logrus.FieldLogger))
	})
	return _c
}

func (_c *MockReconciler_Delete_Call) Return(_a0 error) *MockReconciler_Delete_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockReconciler_Delete_Call) RunAndReturn(run func(context.Context, *apiclient.APIClient, *protoapi.Team, logrus.FieldLogger) error) *MockReconciler_Delete_Call {
	_c.Call.Return(run)
	return _c
}

// Name provides a mock function with given fields:
func (_m *MockReconciler) Name() string {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Name")
	}

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// MockReconciler_Name_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Name'
type MockReconciler_Name_Call struct {
	*mock.Call
}

// Name is a helper method to define mock.On call
func (_e *MockReconciler_Expecter) Name() *MockReconciler_Name_Call {
	return &MockReconciler_Name_Call{Call: _e.mock.On("Name")}
}

func (_c *MockReconciler_Name_Call) Run(run func()) *MockReconciler_Name_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockReconciler_Name_Call) Return(_a0 string) *MockReconciler_Name_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockReconciler_Name_Call) RunAndReturn(run func() string) *MockReconciler_Name_Call {
	_c.Call.Return(run)
	return _c
}

// Reconcile provides a mock function with given fields: ctx, client, naisTeam, log
func (_m *MockReconciler) Reconcile(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger) error {
	ret := _m.Called(ctx, client, naisTeam, log)

	if len(ret) == 0 {
		panic("no return value specified for Reconcile")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *apiclient.APIClient, *protoapi.Team, logrus.FieldLogger) error); ok {
		r0 = rf(ctx, client, naisTeam, log)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockReconciler_Reconcile_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Reconcile'
type MockReconciler_Reconcile_Call struct {
	*mock.Call
}

// Reconcile is a helper method to define mock.On call
//   - ctx context.Context
//   - client *apiclient.APIClient
//   - naisTeam *protoapi.Team
//   - log logrus.FieldLogger
func (_e *MockReconciler_Expecter) Reconcile(ctx interface{}, client interface{}, naisTeam interface{}, log interface{}) *MockReconciler_Reconcile_Call {
	return &MockReconciler_Reconcile_Call{Call: _e.mock.On("Reconcile", ctx, client, naisTeam, log)}
}

func (_c *MockReconciler_Reconcile_Call) Run(run func(ctx context.Context, client *apiclient.APIClient, naisTeam *protoapi.Team, log logrus.FieldLogger)) *MockReconciler_Reconcile_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*apiclient.APIClient), args[2].(*protoapi.Team), args[3].(logrus.FieldLogger))
	})
	return _c
}

func (_c *MockReconciler_Reconcile_Call) Return(_a0 error) *MockReconciler_Reconcile_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockReconciler_Reconcile_Call) RunAndReturn(run func(context.Context, *apiclient.APIClient, *protoapi.Team, logrus.FieldLogger) error) *MockReconciler_Reconcile_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockReconciler creates a new instance of MockReconciler. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockReconciler(t interface {
	mock.TestingT
	Cleanup(func())
},
) *MockReconciler {
	mock := &MockReconciler{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
