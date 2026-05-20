SELECT 'ufid_file' AS table_name, count(*) AS rows FROM ufid_file
UNION ALL
SELECT 'ufid_file_meta', count(*) FROM ufid_file_meta
UNION ALL
SELECT 'ufid_archive_member', count(*) FROM ufid_archive_member
UNION ALL
SELECT 'ufid_identity_conflict', count(*) FROM ufid_identity_conflict
UNION ALL
SELECT 'ufid_source', count(*) FROM ufid_source
UNION ALL
SELECT 'ufid_file_source', count(*) FROM ufid_file_source
UNION ALL
SELECT 'ufid_goldrush_alert', count(*) FROM ufid_goldrush_alert
UNION ALL
SELECT 'ufid_user_account', count(*) FROM ufid_user_account
UNION ALL
SELECT 'ufid_role', count(*) FROM ufid_role
UNION ALL
SELECT 'ufid_user_role', count(*) FROM ufid_user_role
UNION ALL
SELECT 'ufid_session', count(*) FROM ufid_session
UNION ALL
SELECT 'ufid_audit_log', count(*) FROM ufid_audit_log
ORDER BY table_name;
