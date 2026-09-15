from __future__ import annotations

import os
from ansible.plugins.action import ActionBase


class ActionModule(ActionBase):
    TRANSFERS_FILES = True

    def run(self, tmp=None, task_vars=None):
        del tmp
        if task_vars is None:
            task_vars = dict()

        result = super(ActionModule, self).run(None, task_vars)

        src = self._task.args.get('src')
        dest = self._task.args.get('dest')
        mode = self._task.args.get('mode', '0750')
        owner = self._task.args.get('owner')
        group = self._task.args.get('group')

        if not src or not dest:
            result['failed'] = True
            result['msg'] = 'src and dest are required'
            return result

        # Locate source file in role's files/ or playbook paths
        try:
            source = self._find_needle('files', src)
        except Exception:
            source = self._loader.path_dwim(src)

        if not os.path.isfile(source):
            result['failed'] = True
            result['msg'] = (
                f"Source file '{source}' does not exist. "
                "The installer bundle is not tracked in git by default. "
                "Please run 'sh ansible/stage-bundle.sh' (or 'cd ansible && sh stage-bundle.sh') "
                "on the Ansible controller before running playbooks."
            )
            return result

        local_size = str(os.path.getsize(source))

        # Check if remote file exists and compare size for idempotency
        stat_cmd = f"test -f '{dest}' && wc -c < '{dest}' || echo -1"
        stat_res = self._low_level_execute_command(stat_cmd)
        remote_size = stat_res.get('stdout', '').strip().split('\n')[-1].strip()

        if remote_size == local_size:
            result['changed'] = False
        else:
            # Transfer directly via SSH connection (SFTP/SCP) without remote Python
            self._connection.put_file(source, dest)
            result['changed'] = True

        # Enforce permissions and ownership
        cmds = [f"chmod {mode} '{dest}'"]
        if owner and group:
            cmds.append(f"chown {owner}:{group} '{dest}'")
        elif owner:
            cmds.append(f"chown {owner} '{dest}'")
        elif group:
            cmds.append(f"chgrp {group} '{dest}'")

        self._low_level_execute_command(" && ".join(cmds))

        return result
