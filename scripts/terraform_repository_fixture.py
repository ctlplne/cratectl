# SPDX-License-Identifier: BUSL-1.1
"""Exercise the local cratectl provider with stock Terraform and OpenTofu against the owned registry."""
import json
import platform
import shutil

from bounded_client import run_owned_client


SOURCE = 'ctlplne.dev/ctlplne/cratectl'
VERSION = '0.1.0'
RESOURCE = 'cratectl_hosted_repository.owned'


def evaluate_tools(work, clients, provider, env, config, registry_call, sha):
    target = platform.system().lower() + '_' + {'aarch64': 'arm64', 'arm64': 'arm64', 'x86_64': 'amd64'}[platform.machine()]
    mirror = work / 'provider-mirror'
    provider_dir = mirror / SOURCE / VERSION / target
    provider_dir.mkdir(parents=True)
    plugin = provider_dir / ('terraform-provider-cratectl_v' + VERSION)
    shutil.copyfile(provider, plugin)
    plugin.chmod(0o700)
    rc = work / 'terraform.rc'
    rc.write_text('disable_checkpoint = true\nprovider_installation {\n'
                  '  filesystem_mirror {\n'
                  f'    path = {json.dumps(str(mirror))}\n'
                  f'    include = ["{SOURCE}"]\n'
                  '  }\n}\n')
    client_config = work / 'provider-client.json'
    config_bytes = config.read_bytes()
    authority = json.loads(config_bytes)['url']
    client_config.write_bytes(config_bytes)
    results = []
    child_env = {key: value for key, value in env.items()
                 if not key.startswith(('TF_', 'TERRAFORM_', 'TOFU_', 'CHECKPOINT_'))}
    child_env.update(TF_CLI_CONFIG_FILE=str(rc), TF_IN_AUTOMATION='1', CHECKPOINT_DISABLE='1')
    for name, tool in clients:
        folder = work / name
        folder.mkdir()
        checks = []

        def check(label, condition):
            if not condition:
                raise ValueError(name + ' ' + label)
            checks.append(label)

        def cli(label, *args, status=0, cwd=folder):
            with (work / (name + '-' + label + '.log')).open('wb') as log:
                code, output = run_owned_client((str(tool), *args), cwd, child_env, timeout=50,
                                                output_limit=3 << 20, capture_limit=2 << 20, output_sink=log)
            if code != status:
                raise ValueError(f'{name} {label} returned {code}, expected {status}')
            return output

        def hcl(path, repository):
            path.write_text(f'''terraform {{
  required_providers {{
    cratectl = {{
      source  = "{SOURCE}"
      version = "= {VERSION}"
    }}
  }}
}}
provider "cratectl" {{
  client_config = {json.dumps(str(client_config))}
  state_scope   = "cratectl-{name}-provider"
}}
resource "cratectl_hosted_repository" "owned" {{
  authority      = {json.dumps(authority)}
  tenant         = "cratectl-manifest"
  name           = "{repository}"
  format         = "npm"
  access         = "restricted"
  require_review = true
}}
output "lifecycle" {{
  value = cratectl_hosted_repository.owned.lifecycle_state
}}
''')

        current_name = 'cratectl-' + name
        hcl(folder / 'main.tf', current_name)
        version = json.loads(cli('version', 'version', '-json'))['terraform_version']
        cli('init', 'init', '-input=false', '-no-color')
        cli('plan-create', 'plan', '-input=false', '-no-color', '-out=create.tfplan')
        plan = json.loads(cli('show-create', 'show', '-json', 'create.tfplan'))
        changes = [row for row in plan['resource_changes'] if row['address'] == RESOURCE]
        create = changes[0]['change']
        check('saved stock plan binds tenant and registry authority', len(changes) == 1
              and create['actions'] == ['create'] and create['after']['authority'] == authority
              and create['after']['id'] == 'cratectl-manifest/' + current_name
              and create['after']['state_scope'] == 'cratectl-' + name + '-provider')
        endpoint = '/api/v1/repositories/' + current_name
        registry_call(name + '-absent-after-plan', endpoint + '/configuration', status=1)
        check('plan left the registry unchanged', True)
        altered = json.loads(config_bytes)
        altered['url'] = ('https://127.0.0.1:38443' if authority == 'https://localhost:38443'
                          else 'https://localhost:38443')
        client_config.write_text(json.dumps(altered))
        try:
            failed = cli('different-authority-refused', 'apply', '-input=false', '-no-color',
                         'create.tfplan', status=1)
            check('saved plan cannot apply to another bound authority', 'authority differs' in failed)
        finally:
            client_config.write_bytes(config_bytes)
        registry_call(name + '-absent-after-refusal', endpoint + '/configuration', status=1)
        # A failed apply can advance the client's local state serial. Review a
        # fresh saved plan and verify that it still declares the same creation.
        cli('plan-after-refusal', 'plan', '-input=false', '-no-color', '-out=reviewed.tfplan')
        reviewed = json.loads(cli('show-reviewed-create', 'show', '-json', 'reviewed.tfplan'))
        refreshed = [row['change'] for row in reviewed['resource_changes'] if row['address'] == RESOURCE]
        check('retry plan keeps the same reviewed repository identity', refreshed == [create])
        cli('apply-create', 'apply', '-input=false', '-no-color', 'reviewed.tfplan')
        configured = registry_call(name + '-inspect-created', endpoint + '/configuration')
        check('stock apply created the exact hosted review configuration', configured['format'] == 'npm'
              and configured['mode'] == 'hosted' and configured['access'] == 'restricted' and configured['require_review'])
        cli('no-change', 'plan', '-input=false', '-no-color', '-detailed-exitcode')

        # A second state attempts a creation after another operator creates the name.
        competing = folder / 'competing'
        competing.mkdir()
        imported_name = current_name + '-import'
        import_endpoint = '/api/v1/repositories/' + imported_name
        hcl(competing / 'main.tf', imported_name)
        cli('competing-init', 'init', '-input=false', '-no-color', cwd=competing)
        cli('plan-absent-before-other-create', 'plan', '-input=false', '-no-color', '-out=competing.tfplan', cwd=competing)
        registry_call(name + '-create-for-import', '/api/v1/repositories', 'POST',
                      {'name': imported_name, 'format': 'npm', 'mode': 'hosted', 'access': 'restricted', 'require_review': True})
        failed = cli('do-not-adopt-competing-create', 'apply', '-input=false', '-no-color',
                     'competing.tfplan', cwd=competing, status=1)
        check('competing creation is not silently adopted', 'HTTP 409' in failed or 'already retained' in failed)
        cli('import', 'import', '-input=false', '-no-color', RESOURCE, 'cratectl-manifest/' + imported_name, cwd=competing)
        state = json.loads(cli('show-import', 'show', '-json', cwd=competing))
        values = state['values']['root_module']['resources'][0]['values']
        check('explicit import reads the exact existing repository',
              values['id'] == 'cratectl-manifest/' + imported_name and values['lifecycle_state'] == 'active'
              and values['format'] == 'npm' and values['access'] == 'restricted' and values['require_review'])
        cli('import-no-change', 'plan', '-input=false', '-no-color', '-detailed-exitcode', cwd=competing)
        registry_call(name + '-suspend', endpoint + '/state', 'PUT',
                      {'action': 'suspend', 'expected_revision': 0, 'reason': 'Retain stock provider fixture'})
        cli('plan-lifecycle-drift', 'plan', '-refresh-only', '-input=false', '-no-color', '-detailed-exitcode',
            '-out=drift.tfplan', status=2)
        drift_plan = json.loads(cli('show-lifecycle-drift', 'show', '-json', 'drift.tfplan'))
        drift = [row['change'] for row in drift_plan['resource_drift'] if row['address'] == RESOURCE]
        check('read-only refresh exposes exact lifecycle drift', len(drift) == 1
              and drift[0]['before']['lifecycle_state'] == 'active' and drift[0]['after']['lifecycle_state'] == 'suspended'
              and drift[0]['after']['lifecycle_revision'] == 1)
        cli('apply-only-refreshed-state', 'apply', '-input=false', '-no-color', 'drift.tfplan')
        failed = cli('protected-destroy', 'plan', '-destroy', '-input=false', '-no-color', status=1)
        retained = registry_call(name + '-still-retained', endpoint + '/state')
        check('destroy fails and leaves the repository retained', 'retirement requires' in failed
              and retained['state'] == 'suspended' and retained['revision'] == 1)
        results.append({'client': name, 'version': version, 'client_sha256': sha(tool), 'checks': checks})

    return {'provider_sha256': sha(plugin), 'provider_source': SOURCE, 'provider_version': VERSION, 'clients': results}
