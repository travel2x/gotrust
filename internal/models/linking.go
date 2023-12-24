package models

import (
	"github.com/travel2x/gotrust/internal/api/provider"
	"github.com/travel2x/gotrust/internal/conf"
	"github.com/travel2x/gotrust/internal/storage"
	"strings"
)

type AccountLinkingDecision = int

const (
	AccountExists AccountLinkingDecision = iota
	CreateAccount
	LinkAccount
	MultipleAccounts
)

type AccountLinkingResult struct {
	Decision       AccountLinkingDecision
	User           *User
	Identities     []*Identity
	LinkingDomain  string
	CandidateEmail provider.Email
}

func GetAccountLinkingDomain(provider string) string {
	if strings.HasPrefix(provider, "sso:") {
		// when the provider ID is a SSO provider, then the linking
		// domain is the provider itself i.e. there can only be one
		// user + identity per identity provider
		return provider
	}

	// otherwise, the linking domain is the default linking domain that
	// links all accounts
	return "default"
}

func DetermineAccountLinking(tx *storage.Connection, config *conf.GlobalConfiguration, emails []provider.Email, sub, aud, providerName string) (AccountLinkingResult, error) {
	var verifiedEmails []string
	var candidateEmail provider.Email
	for _, email := range emails {
		if email.Verified || config.Mailer.Autoconfirm {
			verifiedEmails = append(verifiedEmails, strings.ToLower(email.Email))
		}
		if email.Primary {
			candidateEmail = email
			candidateEmail.Email = strings.ToLower(candidateEmail.Email)
		}
	}
	if identity, err := FindIdentityByIdAndProvider(tx, sub, providerName); err == nil {
		// it's meant an account exists
		var user *User
		if user, err = FindUserByID(tx, identity.UserID); err != nil {
			return AccountLinkingResult{}, err
		}

		candidateEmail.Email = user.GetEmail()
		return AccountLinkingResult{
			Decision:       AccountExists,
			User:           user,
			Identities:     []*Identity{identity},
			LinkingDomain:  GetAccountLinkingDomain(providerName),
			CandidateEmail: candidateEmail,
		}, nil
	} else if !IsNotFoundError(err) {
		return AccountLinkingResult{}, err
	}
	// the identity does not exist, so we need to check if we should create a new account
	// or link to an existing one
	candidateLinkingDomain := GetAccountLinkingDomain(providerName)
	if len(verifiedEmails) == 0 {
		user, err := IsDuplicatedEmail(tx, candidateEmail.Email, aud, nil)
		if err != nil {
			return AccountLinkingResult{}, err
		}
		if user != nil {
			candidateEmail.Email = ""
		}
		return AccountLinkingResult{
			Decision:       CreateAccount,
			LinkingDomain:  candidateLinkingDomain,
			CandidateEmail: candidateEmail,
		}, nil
	}

	var similarIdentities []*Identity
	var similarUsers []*User

	if err := tx.Q().Eager().Where("email ilike any (?)", verifiedEmails).All(&similarIdentities); err != nil {
		return AccountLinkingResult{}, err
	}
	if !strings.HasPrefix(providerName, "sso:") {
		// there can be multiple user accounts with the same email when is_sso_user is true,
		// so we just do not consider those similar user accounts
		if err := tx.Q().Eager().Where("email ilike any (?) and is_sso_user is false", verifiedEmails).All(&similarUsers); err != nil {
			return AccountLinkingResult{}, err
		}
	}
	// Need to check if the new identity should be assigned to an
	// existing user or to create a new user, according to the automatic linking rules
	var linkingIdentities []*Identity
	for _, identity := range similarIdentities {
		if GetAccountLinkingDomain(identity.Provider) == candidateLinkingDomain {
			linkingIdentities = append(linkingIdentities, identity)
		}
	}
	if len(linkingIdentities) == 0 {
		if len(similarUsers) == 1 {
			// no similarIdentities but a user with the same email exists
			// so we link this new identity to the user
			// TODO: Backfield the missing identity for the user
			return AccountLinkingResult{
				Decision:       LinkAccount,
				User:           similarUsers[0],
				Identities:     linkingIdentities,
				LinkingDomain:  candidateLinkingDomain,
				CandidateEmail: candidateEmail,
			}, nil
		} else if len(similarUsers) > 1 {
			// this shouldn't happen since there is a partial unique index on (email and is_sso_user = false)
			return AccountLinkingResult{
				Decision:       MultipleAccounts,
				Identities:     linkingIdentities,
				LinkingDomain:  candidateLinkingDomain,
				CandidateEmail: candidateEmail,
			}, nil
		} else {
			// there are no identities in the linking domain, we have to
			// create a new identity and new user
			return AccountLinkingResult{
				Decision:       CreateAccount,
				LinkingDomain:  candidateLinkingDomain,
				CandidateEmail: candidateEmail,
			}, nil
		}
	}

	// there is at least one identity in the linking domain let's do a
	// sanity check to see if all of the identities in the domain share the
	// same user ID
	linkingUserId := linkingIdentities[0].UserID
	for _, identity := range linkingIdentities {
		if identity.UserID != linkingUserId {
			// ok, this linking domain has more than one user account
			// caller should decide what to do

			return AccountLinkingResult{
				Decision:       MultipleAccounts,
				Identities:     linkingIdentities,
				LinkingDomain:  candidateLinkingDomain,
				CandidateEmail: candidateEmail,
			}, nil
		}
	}

	// there's only one user ID in this linking domain, we can go on and
	// create a new identity and link it to the existing account

	var user *User
	var err error

	if user, err = FindUserByID(tx, linkingUserId); err != nil {
		return AccountLinkingResult{}, err
	}

	return AccountLinkingResult{
		Decision:       LinkAccount,
		User:           user,
		Identities:     linkingIdentities,
		LinkingDomain:  candidateLinkingDomain,
		CandidateEmail: candidateEmail,
	}, nil

}
