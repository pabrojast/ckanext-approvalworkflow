from flask import Blueprint
import ckantoolkit as tk


approval_workflow = Blueprint('approval_workflow', __name__)


def index():
    return tk.render('approval_workflow/index.html')

approval_workflow.add_url_rule("/workflow", view_func=index)