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

import (
	"encoding/json"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
)

func TestTenantWithoutMfaPolicy(t *testing.T) {
	organization := &Organization{
		Name: "tenant-free",
	}
	user := &User{
		Owner: organization.Name,
		Name:  "free-user",
	}

	if IsNeedPromptMfa(organization, user) {
		t.Fatal("an organization without MFA items must not require MFA")
	}
	for _, mfaType := range []string{SmsType, EmailType, TotpType, RadiusType, PushType, WebAuthnType} {
		if !IsMfaTypeAllowed(organization, user, mfaType) {
			t.Fatalf("an empty MFA policy must allow the %s factor", mfaType)
		}
	}
}

func TestTenantRequiredTotpMfa(t *testing.T) {
	organization := &Organization{
		Name: "tenant-totp",
		MfaItems: []*MfaItem{
			{Name: TotpType, Rule: "Required"},
		},
	}
	pendingUser := &User{
		Owner: organization.Name,
		Name:  "pending-user",
	}
	enrolledUser := &User{
		Owner:      organization.Name,
		Name:       "enrolled-user",
		TotpSecret: "JBSWY3DPEHPK3PXP",
	}

	if !IsNeedPromptMfa(organization, pendingUser) {
		t.Fatal("a tenant requiring TOTP must prompt a user without TOTP")
	}
	if IsNeedPromptMfa(organization, enrolledUser) {
		t.Fatal("a tenant requiring TOTP must not prompt a user who enrolled TOTP")
	}
	if !IsMfaTypeAllowed(organization, pendingUser, TotpType) {
		t.Fatal("the required TOTP factor must be available")
	}
	if IsMfaTypeAllowed(organization, pendingUser, WebAuthnType) {
		t.Fatal("a TOTP-only tenant must not offer WebAuthn as an MFA factor")
	}
}

func TestTenantRequiredWebAuthnMfa(t *testing.T) {
	organization := &Organization{
		Name: "tenant-webauthn",
		MfaItems: []*MfaItem{
			{Name: WebAuthnType, Rule: "Required"},
		},
	}
	pendingUser := &User{
		Owner: organization.Name,
		Name:  "pending-user",
	}
	enrolledUser := &User{
		Owner: organization.Name,
		Name:  "enrolled-user",
		WebauthnCredentials: []webauthn.Credential{
			{ID: []byte("credential-id")},
		},
	}

	if !IsNeedPromptMfa(organization, pendingUser) {
		t.Fatal("a tenant requiring WebAuthn must prompt a user without a passkey")
	}
	if IsNeedPromptMfa(organization, enrolledUser) {
		t.Fatal("a tenant requiring WebAuthn must not prompt a user who enrolled WebAuthn MFA")
	}
	if !IsMfaTypeAllowed(organization, pendingUser, WebAuthnType) {
		t.Fatal("the required WebAuthn factor must be available")
	}
	if !enrolledUser.IsMfaEnabled() || !enrolledUser.IsWebAuthnMfaEnabled() {
		t.Fatal("the enrolled user must be recognized as MFA-enabled")
	}
	if prop := enrolledUser.GetMfaProps(WebAuthnType, true); !prop.Enabled || prop.MfaType != WebAuthnType {
		t.Fatalf("unexpected WebAuthn MFA properties: %+v", prop)
	}

	otherTenantUser := &User{
		Owner: "tenant-free",
		Name:  "other-user",
	}
	if IsNeedPromptMfa(organization, otherTenantUser) {
		t.Fatal("a WebAuthn MFA policy must not leak into another tenant")
	}

	payload, err := json.Marshal(MfaItem{Name: WebAuthnType, Rule: "Required"})
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != `{"name":"webauthn","rule":"Required"}` {
		t.Fatalf("the WebAuthn MFA item broke the existing API shape: %s", payload)
	}
}
