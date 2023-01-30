def initdb():
    import ckanext.approvalworkflow.db as db
    db.init_db()