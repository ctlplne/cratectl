#!/usr/bin/env python3
"""Fail before a commit or push can use the wrong repository identity."""
import subprocess,sys
NAME='imfeelingtheagi'
EMAIL='288773099+imfeelingtheagi@users.noreply.github.com'
expected=NAME+' <'+EMAIL+'> '
for variable in ['GIT_AUTHOR_IDENT','GIT_COMMITTER_IDENT']:
    actual=subprocess.check_output(['git','var',variable],text=True)
    if not actual.startswith(expected):
        raise SystemExit('Commit blocked: '+variable+' must use '+NAME+' <'+EMAIL+'>')
if '--history' in sys.argv:
    rows=subprocess.check_output(['git','log','--format=%H%x09%an%x09%ae%x09%cn%x09%ce','HEAD'],text=True)
    for row in rows.splitlines():
        commit,author,email,committer,committer_email=row.split('\t')
        if (author,email,committer,committer_email)!=(NAME,EMAIL,NAME,EMAIL):
            raise SystemExit('Push blocked: incorrect identity on '+commit)
