import sys

from ckan.plugins.toolkit import CkanCommand
import ckanext.approvalworkflow.utils as utils


class ApprovalWorkflowCommand(CkanCommand):
    """Adds approval workflow for datasets to ckan

    Usage:

        approval_workflow initdb
        - Creates the necessary tables in the database
    """
    summary = __doc__.split('\n')[0]
    usage = __doc__
    max_args = 1
    min_args = 0

    def __init__(self, name):
        super(ApprovalWorkflowCommand, self).__init__(name)

    def command(self):
        self._load_config()

        if len(self.args) == 0:
            self.parser.print_usage()
            sys.exit(1)
        cmd = self.args[0]

        if cmd == "initdb":
            self.initdb()
        else:
            print("Command {0} not recognized".format(cmd))

    def initdb(self):
        utils.initdb()
        print("Approval Workflow DB tables created")
