package openstack

import (
	"context"
	"fmt"

	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/projects"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/roles"
)

// FindProject resolves a Keystone project by name, reporting whether
// one exists.
func (o *Cloud) FindProject(ctx context.Context, name string) (string, bool, error) {
	pages, err := projects.List(o.identity, projects.ListOpts{Name: name}).AllPages(ctx)
	if err != nil {
		return "", false, fmt.Errorf("openstack: list projects: %w", err)
	}
	all, err := projects.ExtractProjects(pages)
	if err != nil {
		return "", false, fmt.Errorf("openstack: extract projects: %w", err)
	}
	if len(all) == 0 {
		return "", false, nil
	}
	return all[0].ID, true, nil
}

// CreateProject creates a scenario project. Scenario projects outlive
// their run deliberately — see the description text.
func (o *Cloud) CreateProject(ctx context.Context, name string) (string, error) {
	enabled := true
	p, err := projects.Create(ctx, o.identity, projects.CreateOpts{
		Name:        name,
		Enabled:     &enabled,
		Description: "scenariotest live-validation project (not torn down)",
	}).Extract()
	if err != nil {
		return "", fmt.Errorf("openstack: create project %q: %w", name, err)
	}
	return p.ID, nil
}

// GrantAdminRole gives the authenticated admin user the admin role on
// projectID — the prerequisite for [Cloud.scopedFor] to mint a
// project-scoped token. The role id is resolved once and cached.
func (o *Cloud) GrantAdminRole(ctx context.Context, projectID string) error {
	if o.adminRoleID == "" {
		pages, err := roles.List(o.identity, roles.ListOpts{Name: "admin"}).AllPages(ctx)
		if err != nil {
			return fmt.Errorf("openstack: list roles: %w", err)
		}
		rs, err := roles.ExtractRoles(pages)
		if err != nil {
			return fmt.Errorf("openstack: extract roles: %w", err)
		}
		if len(rs) == 0 {
			return fmt.Errorf("openstack: role \"admin\" not found")
		}
		o.adminRoleID = rs[0].ID
	}
	err := roles.Assign(ctx, o.identity, o.adminRoleID, roles.AssignOpts{
		UserID:    o.userID,
		ProjectID: projectID,
	}).ExtractErr()
	if err != nil {
		return fmt.Errorf("openstack: grant admin role on project %s: %w", projectID, err)
	}
	return nil
}
