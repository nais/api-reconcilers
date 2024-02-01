package reconcilers

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/nais/api/pkg/apiclient"
	"github.com/nais/api/pkg/protoapi"
)

func AuditLogForTeam(ctx context.Context, apiclient *apiclient.APIClient, reconciler Reconciler, action, teamSlug, msg string, a ...any) {
	targets := []*protoapi.AuditLogTarget{
		{AuditLogTargetType: &protoapi.AuditLogTarget_TeamSlug{TeamSlug: teamSlug}},
	}
	createAuditLog(ctx, apiclient, reconciler, action, targets, msg, a...)
}

func AuditLogForTeamAndUser(ctx context.Context, apiclient *apiclient.APIClient, reconciler Reconciler, action, teamSlug, user, msg string, a ...any) {
	targets := []*protoapi.AuditLogTarget{
		{AuditLogTargetType: &protoapi.AuditLogTarget_TeamSlug{TeamSlug: teamSlug}},
		{AuditLogTargetType: &protoapi.AuditLogTarget_User{User: user}},
	}
	createAuditLog(ctx, apiclient, reconciler, action, targets, msg, a...)
}

func createAuditLog(ctx context.Context, apiclient *apiclient.APIClient, reconciler Reconciler, action string, targets []*protoapi.AuditLogTarget, msg string, a ...any) {
	correlationID, ok := ctx.Value(ctxCorrelationID).(string)
	if !ok {
		correlationID = uuid.New().String()
	}

	_, _ = apiclient.AuditLogs().Create(ctx, &protoapi.CreateAuditLogsRequest{
		Targets:        targets,
		Action:         action,
		CorrelationId:  correlationID,
		ReconcilerName: reconciler.Name(),
		Message:        fmt.Sprintf(msg, a...),
	})
}
