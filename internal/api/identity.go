package api

import (
	"context"
	"github.com/fatih/structs"
	"github.com/travel2x/gotrust/internal/api/provider"
	"github.com/travel2x/gotrust/internal/models"
	"github.com/travel2x/gotrust/internal/storage"
)

func (a *API) linkIdentityToUser(ctx context.Context, tx *storage.Connection, userData *provider.UserProvidedData, providerType string) (*models.User, error) {
	targetUser := getTargetUser(ctx)
	identity, err := models.FindIdentityByIdAndProvider(tx, userData.Metadata.Subject, providerType)
	if err != nil {
		if !models.IsNotFoundError(err) {
			return nil, internalServerError("Database error finding identity for linking").WithInternalError(err)
		}
	}

	if identity != nil {
		if identity.UserID == targetUser.ID {
			return nil, badRequestError("Identity is already linked")
		}
		return nil, badRequestError("Identity is already linked to another user")
	}

	if _, err := a.CreateNewIdentity(tx, targetUser, providerType, structs.Map(userData.Metadata)); err != nil {
		return nil, err
	}

	if err := targetUser.UpdateAppMetaDataProviders(tx); err != nil {
		return nil, err
	}
	return targetUser, nil
}
