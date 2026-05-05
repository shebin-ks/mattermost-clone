// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package oauthgoogle

import (
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/shared/mlog"
	"github.com/mattermost/mattermost/server/public/shared/request"
	"github.com/mattermost/mattermost/server/v8/einterfaces"
)

type GoogleProvider struct{}

type GoogleUser struct {
	ResourceName   string        `json:"resourceName"` // e.g. "people/1234567"
	Sub            string        `json:"sub"`
	Id             string        `json:"id"`
	Email          string        `json:"email"`
	Name           string        `json:"name"`
	GivenName      string        `json:"given_name"`
	FamilyName     string        `json:"family_name"`
	Picture        string        `json:"picture"`
	Names          []GoogleName  `json:"names"`
	EmailAddresses []GoogleEmail `json:"emailAddresses"`
	Nicknames      []GoogleNick  `json:"nicknames"`
}

type GoogleName struct {
	GivenName   string `json:"givenName"`
	FamilyName  string `json:"familyName"`
	DisplayName string `json:"displayName"`
}

type GoogleEmail struct {
	Value    string `json:"value"`
	Metadata struct {
		Primary bool `json:"primary"`
	} `json:"metadata"`
}

type GoogleNick struct {
	Value string `json:"value"`
}

func init() {
	einterfaces.RegisterOAuthProvider(model.ServiceGoogle, &GoogleProvider{})
}

func (gu *GoogleUser) IsValid() error {
	if gu.ResourceName == "" && gu.Sub == "" && gu.Id == "" {
		return errors.New("google user identifier (resourceName, sub, or id) cannot be empty")
	}
	if len(gu.EmailAddresses) == 0 && gu.Email == "" {
		return errors.New("google user has no email address")
	}
	return nil
}

func (gu *GoogleUser) getAuthData() string {
	if gu.ResourceName != "" {
		// Strip "people/" prefix to get the numeric ID
		return strings.TrimPrefix(gu.ResourceName, "people/")
	}
	if gu.Sub != "" {
		return gu.Sub
	}
	return gu.Id
}

func (gu *GoogleUser) getPrimaryEmail() string {
	for _, e := range gu.EmailAddresses {
		if e.Metadata.Primary {
			return strings.ToLower(e.Value)
		}
	}
	if len(gu.EmailAddresses) > 0 {
		return strings.ToLower(gu.EmailAddresses[0].Value)
	}
	if gu.Email != "" {
		return strings.ToLower(gu.Email)
	}
	return ""
}

func (gp *GoogleProvider) GetUserFromJSON(rctx request.CTX, data io.Reader, tokenUser *model.User, settings *model.SSOSettings) (*model.User, error) {
	b, _ := io.ReadAll(data)
	rctx.Logger().Warn("Google OAuth Raw JSON Response", mlog.String("json", string(b)))

	var gu GoogleUser
	if err := json.Unmarshal(b, &gu); err != nil {
		return nil, err
	}
	if err := gu.IsValid(); err != nil {
		rctx.Logger().Warn("Google OAuth Validation Failed", mlog.Err(err), mlog.String("json", string(b)))
		return nil, err
	}

	user := &model.User{}
	user.Email = gu.getPrimaryEmail()

	if len(gu.Names) > 0 {
		user.FirstName = gu.Names[0].GivenName
		user.LastName = gu.Names[0].FamilyName
	} else if gu.GivenName != "" || gu.FamilyName != "" {
		user.FirstName = gu.GivenName
		user.LastName = gu.FamilyName
	} else if gu.Name != "" {
		nameParts := strings.SplitN(gu.Name, " ", 2)
		if len(nameParts) > 0 {
			user.FirstName = nameParts[0]
			if len(nameParts) > 1 {
				user.LastName = nameParts[1]
			}
		}
	}

	authData := gu.getAuthData()
	user.AuthData = &authData
	user.AuthService = model.ServiceGoogle

	// Build username from email prefix
	if user.Email != "" {
		user.Username = model.CleanUsername(rctx.Logger().(mlog.LoggerIFace), strings.Split(user.Email, "@")[0])
	}

	return user, nil
}

func (gp *GoogleProvider) GetSSOSettings(_ request.CTX, config *model.Config, service string) (*model.SSOSettings, error) {
	return &config.GoogleSettings, nil
}

func (gp *GoogleProvider) GetUserFromIdToken(_ request.CTX, idToken string) (*model.User, error) {
	return nil, nil
}

func (gp *GoogleProvider) IsSameUser(_ request.CTX, dbUser, oAuthUser *model.User) bool {
	return dbUser.AuthData == oAuthUser.AuthData
}
