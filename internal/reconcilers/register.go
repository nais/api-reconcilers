package reconcilers

// func Register(ctx context.Context, client protoapi.ReconcilersClient) error {
// 	_, err := client.Register(ctx, &protoapi.RegisterReconcilerRequest{
// 		Reconcilers: []*protoapi.NewReconciler{
// 			{
// 				Name:        "azure:group",
// 				DisplayName: "Azure AD groups",
// 				Description: "Create and maintain Azure AD security groups for the Console teams.",
// 				Config: []*protoapi.ReconcilerConfig{
// 					{
// 						Key:         "azure:client_secret",
// 						DisplayName: "Client secret",
// 						Description: "The client secret of the application registration.",
// 						Secret:      true,
// 					},
// 					{
// 						Key:         "azure:client_id",
// 						DisplayName: "Client ID",
// 						Description: "The client ID of the application registration that Console will use when communicating with the Azure AD APIs. The application must have the following API permissions: Group.Create, GroupMember.ReadWrite.All.",
// 						Secret:      false,
// 					},
// 					{
// 						Key:         "azure:tenant_id",
// 						DisplayName: "Tenant ID",
// 						Description: "The ID of the Azure AD tenant.",
// 						Secret:      false,
// 					},
// 				},
// 			},
// 			{
// 				Name:        "google:workspace-admin",
// 				DisplayName: "Google workspace group",
// 				Description: "Create and maintain Google workspace groups for the Console teams.",
// 				Enabled:     false,
// 			},
// 			{
// 				Name:        "google:gcp:project",
// 				DisplayName: "GCP projects",
// 				Description: "Create GCP projects for the Console teams.",
// 				Enabled:     false,
// 			},
// 			{
// 				Name:        "nais:namespace",
// 				DisplayName: "NAIS namespace",
// 				Description: "Create NAIS namespaces for the Console teams.",
// 				Enabled:     false,
// 			},
// 			{
// 				Name:        "nais:deploy",
// 				DisplayName: "NAIS deploy",
// 				Description: "Provision NAIS deploy key for Console teams.",
// 				Enabled:     false,
// 			},
// 			{
// 				Name:        "google:gcp:gar",
// 				DisplayName: "Google Artifact Registry",
// 				Description: "Provision artifact registry repositories for Console teams.",
// 				Enabled:     false,
// 			},
// 			{
// 				Name:        "nais:dependencytrack",
// 				DisplayName: "DependencyTrack",
// 				Description: "Create teams and users in dependencytrack",
// 				Enabled:     false,
// 			},
// 		},
// 	})
// 	return err
// }
