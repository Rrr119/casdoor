// Copyright 2026 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package object

import "errors"

type WebauthnMfa struct {
	*MfaProps
}

func (mfa *WebauthnMfa) Initiate(userId string, issuer string) (*MfaProps, error) {
	return &MfaProps{
		MfaType: WebAuthnType,
	}, nil
}

func (mfa *WebauthnMfa) SetupVerify(passcode string, lang string) error {
	return errors.New("WebAuthn MFA must be set up with the WebAuthn signup API")
}

func (mfa *WebauthnMfa) Enable(user *User) error {
	if len(user.WebauthnCredentials) == 0 {
		return errors.New("no WebAuthn credential has been registered")
	}

	columns := []string{"preferred_mfa_type"}
	if user.PreferredMfaType == "" {
		user.PreferredMfaType = WebAuthnType
	}

	_, err := UpdateUser(user.GetId(), user, columns, false)
	return err
}

func (mfa *WebauthnMfa) Verify(passcode string, lang string) error {
	return errors.New("WebAuthn assertions must be verified with the WebAuthn signin API")
}

func NewWebauthnMfaUtil(config *MfaProps) *WebauthnMfa {
	if config == nil {
		config = &MfaProps{
			MfaType: WebAuthnType,
		}
	}
	return &WebauthnMfa{
		MfaProps: config,
	}
}
