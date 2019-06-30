// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/lucas-clemente/quic-go/internal/handshake (interfaces: LongHeaderOpener)

// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	protocol "github.com/lucas-clemente/quic-go/internal/protocol"
)

// MockLongHeaderOpener is a mock of LongHeaderOpener interface
type MockLongHeaderOpener struct {
	ctrl     *gomock.Controller
	recorder *MockLongHeaderOpenerMockRecorder
}

// MockLongHeaderOpenerMockRecorder is the mock recorder for MockLongHeaderOpener
type MockLongHeaderOpenerMockRecorder struct {
	mock *MockLongHeaderOpener
}

// NewMockLongHeaderOpener creates a new mock instance
func NewMockLongHeaderOpener(ctrl *gomock.Controller) *MockLongHeaderOpener {
	mock := &MockLongHeaderOpener{ctrl: ctrl}
	mock.recorder = &MockLongHeaderOpenerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockLongHeaderOpener) EXPECT() *MockLongHeaderOpenerMockRecorder {
	return m.recorder
}

// DecryptHeader mocks base method
func (m *MockLongHeaderOpener) DecryptHeader(arg0 []byte, arg1 *byte, arg2 []byte) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "DecryptHeader", arg0, arg1, arg2)
}

// DecryptHeader indicates an expected call of DecryptHeader
func (mr *MockLongHeaderOpenerMockRecorder) DecryptHeader(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DecryptHeader", reflect.TypeOf((*MockLongHeaderOpener)(nil).DecryptHeader), arg0, arg1, arg2)
}

// Open mocks base method
func (m *MockLongHeaderOpener) Open(arg0, arg1 []byte, arg2 protocol.PacketNumber, arg3 []byte) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Open", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Open indicates an expected call of Open
func (mr *MockLongHeaderOpenerMockRecorder) Open(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Open", reflect.TypeOf((*MockLongHeaderOpener)(nil).Open), arg0, arg1, arg2, arg3)
}