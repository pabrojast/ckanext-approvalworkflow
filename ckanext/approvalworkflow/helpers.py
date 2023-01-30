import ckanext.approvalworkflow.db as db
from ckan.plugins import toolkit

def get_approvalworkflow_info(context, pkg_id):
    package = toolkit.get_action('package_show')(None, {'id': pkg_id})
    owner_org = package['owner_org']

    aw_model = db.ApprovalWorkflowOrganization.get(organization_id=owner_org)
    if aw_model:
        aw_settings = db.table_dictize(aw_model, context)

        return aw_settings

