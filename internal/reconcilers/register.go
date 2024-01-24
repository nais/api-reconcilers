package reconcilers

// func Register(ctx context.Context, client protoapi.ReconcilersClient) error {
// 	_, err := client.Register(ctx, &protoapi.RegisterReconcilerRequest{
// 		Reconcilers: []*protoapi.NewReconciler{
//
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
