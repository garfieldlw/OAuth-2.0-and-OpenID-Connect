package service

import (
	"fmt"

	"github.com/garfieldlw/OAuth-2.0-and-OpenID-Connect/internal/model"
	"github.com/garfieldlw/OAuth-2.0-and-OpenID-Connect/internal/server"
)

type UserInfoService struct {
	Server    *server.Server
	UserStore *model.UserStore
}

func NewUserInfoService(srv *server.Server, userStore *model.UserStore) *UserInfoService {
	return &UserInfoService{Server: srv, UserStore: userStore}
}

func (s *UserInfoService) GetUserInfo(authHeader string) (*model.UserInfoResponse, error) {
	ti, err := s.Server.ValidateBearerToken(authHeader)
	if err != nil {
		return nil, fmt.Errorf("invalid_token: %v", err)
	}

	if !server.ContainsScope(ti.Scope, "openid") {
		return nil, fmt.Errorf("invalid_scope: openid scope is required for UserInfo endpoint per OIDC Core 1.0 §5.1")
	}

	userID := ti.UserID
	user, ok := s.UserStore.GetByID(userID)
	if !ok {
		return nil, fmt.Errorf("user_not_found: user not found")
	}

	return &model.UserInfoResponse{
		Sub:          userID,
		Name:         user.Name,
		Email:        user.Email,
		EmailVerified: user.Email != "",
	}, nil
}
