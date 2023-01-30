import datetime
import ast

import ckan.plugins.toolkit as toolkit

import ckanext.approvalworkflow.db as db


ValidationError = toolkit.ValidationError
asbool = toolkit.asbool


def workflow(self, context):
    session = context.get('session')
    approval_workflow = ApprovalWorkflow()

    return


def save_workflow_options(self, context, data_dict):
    session = context.get('session')
    db_model = db.ApprovalWorkflow().get()

    aw_active = data_dict.get("approval_workflow_active")

    if aw_active != '1':
        db_model.active = True
        db_model.approval_workflow_active = aw_active
        db_model.deactivate_edit = bool(data_dict.get("ckan.edit-button"))
        
        if aw_active == '3':
            db_model.active_per_organization = True
        else:
            db_model.active_per_organization = False

    db_model.save()
    return


def save_org_workflow_options(self, context, data_dict):
    session = context.get('session')
    organization = data_dict['organization']

    approval_workflow = db.ApprovalWorkflow().get()

    if approval_workflow:
        aw_dict = db.table_dictize(approval_workflow, context)

        db_model = db.ApprovalWorkflowOrganization.get(organization_id=organization)
        if not db_model:
            db_model = db.ApprovalWorkflowOrganization()

        aw_active = data_dict.get("approval_workflow_active")
        
        if aw_active == '2':
            db_model.active = True
            db_model.approval_workflow_id = approval_workflow
            db_model.organization_id = organization
            db_model.org_approval_workflow_active = aw_active
            db_model.deactivate_edit = bool(data_dict.get("ckan.edit-button"))
        else:
            db_model.active = False
            db_model.approval_workflow_id = approval_workflow
            db_model.org_approval_workflow_active = aw_active
            db_model.organization_id = organization
            db_model.deactivate_edit = False     

        db_model.save()
    return    