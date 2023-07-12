IP_V4 = 4
IP_V6 = 6
IP_V4_AND_6 = 46

files = {
    "/etc/network/if-up.d/restore-iptables": {
        'source': "restore-iptables",
        'content_type': 'text',
        'mode': "0775",
        'owner': "root",
        'group': "root",
    },
    "/etc/network/if-pre-up.d/restore-iptables": {
        'delete': True,
    },
    "/usr/local/sbin/iptables-enforce": {
        'delete': True,
    },
    "/usr/local/sbin/iptables-clear": {
        'delete': True,
    },
}

directories = {
    "/etc/network/iptables-rules.d": {
        'purge': True,
    }
}

check = False
port = None
if node.has_bundle('openssh'):
    port = node.metadata.get('openssh', {}).get('port', 22)
    check = True

if 'check' in node.metadata.get('iptables', {}):
    check = node.metadata['iptables']['check']

if 'check_port' in node.metadata.get('iptables', {}):
    port = node.metadata['iptables']['check_port']


iptables = {
    'filter': {
        'check': check,
        'check_port': port,
        'chains': {
            # open up local loopback
            'INPUT': {
                'policy': node.metadata.get('iptables', {}).get('policies', {}).get('filter', {}).get('INPUT', 'DROP'),
                'rules': [
                    repo.libs.iptables.accept().input('lo'),
                ],
                'ignored_rules': [],
                'ignore': False,
            },
            # insert forward rules for sorting correctly
            'FORWARD': {
                'policy': node.metadata.get('iptables', {}).get('policies', {}).get('filter', {}).get('FORWARD', 'DROP'),
                'rules': [
                ],
                'ignored_rules': [],
                'ignore': False,
            },
            # open up local loopback
            'OUTPUT': {
                'policy': node.metadata.get('iptables', {}).get('policies', {}).get('filter', {}).get('OUTPUT', 'DROP'),
                'rules': [
                    repo.libs.iptables.accept().output('lo'),
                ],
                'ignored_rules': [],
                'ignore': False,
            },
            # Chain for DoS protection
            'LOGDROP': {
                'policy': node.metadata.get('iptables', {}).get('policies', {}).get('filter', {}).get('LOGDROP', '-'),
                'rules': [
                    repo.libs.iptables.log(),
                    repo.libs.iptables.drop(),
                ],
                'ignored_rules': [],
                'ignore': False,
            },
        }
    }
}

default_table = {
    'check': check,
    'check_port': port,
    'chains': {}
}

# Set Up counting rules
for interface in sorted(node.metadata.get('interfaces', {}).keys()):
    # allow ICMP
    iptables['filter']['chains']['INPUT']['rules'].append(
        repo.libs.iptables.accept().input(interface).version(4).protocol('icmp')
    )
    iptables['filter']['chains']['INPUT']['rules'].append(
        repo.libs.iptables.accept().input(interface).version(6).protocol('ipv6-icmp')
    )
    iptables['filter']['chains']['OUTPUT']['rules'].append(
        repo.libs.iptables.accept().output(interface).version(6).protocol('ipv6-icmp')
    )

    for ip in node.metadata['interfaces'][interface].get('ip_addresses', []):
        iptables['filter']['chains']['INPUT']['rules'].append(repo.libs.iptables.count().destination(ip))
        iptables['filter']['chains']['OUTPUT']['rules'].append(repo.libs.iptables.count().source(ip))
    for ip in node.metadata['interfaces'][interface].get('ipv6_addresses', []):
        iptables['filter']['chains']['INPUT']['rules'].append(repo.libs.iptables.count().destination(ip))
        iptables['filter']['chains']['OUTPUT']['rules'].append(repo.libs.iptables.count().source(ip))

# allow outgoing connections and answers
for interface in sorted(node.metadata.get('interfaces', {}).keys()):
    iptables['filter']['chains']['INPUT']['rules'].append(
        repo.libs.iptables.accept().input(interface).state('RELATED,ESTABLISHED')
    )
    iptables['filter']['chains']['OUTPUT']['rules'].append(
        repo.libs.iptables.accept().output(interface).state('NEW,RELATED,ESTABLISHED')
    )

# create policy rules
for table in node.metadata.get('iptables', {}).get('policies', {}):
    # set default table
    iptables.setdefault(table, default_table.copy())

    for chain in node.metadata['iptables']['policies'][table].keys():
        policy = node.metadata['iptables']['policies'][table][chain]

        if chain not in iptables[table]['chains']:
            iptables[table]['chains'][chain] = {
                'policy': policy,
                'rules': [],
                'ignored_rules': [],
                'ignore': False,
            }

# add rules from metadata
for rule in sorted(node.metadata.get('iptables', {}).get('rules', []), key=repo.libs.iptables.convert_to_iptables_rule):
    table = rule.get('table', 'filter')

    # set default table
    iptables.setdefault(table, default_table.copy())

    chain = rule.pop('chain', 'INPUT')
    if chain not in iptables[table]['chains']:
        iptables[table]['chains'][chain] = {
            'policy': node.metadata.get('iptables', {}).get('policies', {}).get(table, {}).get(chain, 'ACCEPT'),
            'rules': [],
            'ignored_rules': [],
            'ignore': False,
        }

    # generate copy to manipulate
    rule_copy = rule.copy()

    # legacy only has interface and no input/output rules
    interface = rule_copy.pop('interface', None)
    if interface:
        # set jump to ACCEPT, since legacy rules do not have ACCEPT header
        rule_copy['jump'] = rule.get('jump', 'ACCEPT')

        if chain == 'INPUT' or chain == 'FORWARD':
            rule_copy['input'] = interface
        elif chain == 'OUTPUT':
            rule_copy['output'] = interface

    port = rule_copy.pop('port', None)
    if port:
        proto = rule.get('protocol', 'tcp')
        direction = 'dest' if chain == 'INPUT' or chain == 'FORWARD' else 'src'
        if proto in ['tcp', 'udp']:
            # we need proto to be set otherwise iptables crashes
            rule_copy['protocol'] = proto
            rule_copy['{proto}_{dir}_port'.format(proto=proto, dir=direction)] = port

    # replace main_interface with configured
    if rule.get('input', '') == 'main_interface':
        rule_copy['input'] = node.metadata['main_interface']

    if rule.get('output', '') == 'main_interface':
        rule_copy['output'] = node.metadata['main_interface']

    # replace public_interface with configured
    if rule.get('input', '') == 'public_interface':
        rule_copy['input'] = node.metadata['network']['public_interface']

    if rule.get('output', '') == 'public_interface':
        rule_copy['output'] = node.metadata['network']['public_interface']

    # replace source == friendlies with configured networks
    if rule.get('source', "") == "friendlies":
        # if version is not set, we want both
        if rule_copy.get('version', 4) == 4:
            # ipv4 only
            for friendly_range in node.metadata.get('friendly_ipv4', []):
                rule_copy['source'] = friendly_range
                iptables[table]['chains'][chain]['rules'].append(rule_copy.copy())

        # if version is not set, we want both
        if rule_copy.get('version', 6) == 6:
            # ipv6 only
            for friendly_range in node.metadata.get('friendly_ipv6', []):
                rule_copy['source'] = friendly_range
                iptables[table]['chains'][chain]['rules'].append(rule_copy.copy())

    else:
        iptables[table]['chains'][chain]['rules'].append(rule_copy.copy())

# generate ignored Chains
for chain in node.metadata.get('iptables', {}).get('ignored', {}).get('chains', {}):
    if isinstance(chain, dict):
        table = chain.get('table', 'filter')
        chain = chain.get('chain', None)
    else:
        table = 'filter'

    # no chain set
    if chain is None:
        continue

    # if we have no rules for this table, we skip this ignored rule
    if table not in iptables:
        continue

    if chain not in iptables[table]['chains']:
        iptables[table]['chains'][chain] = {
            'policy': node.metadata.get('iptables', {}).get('policies', {}).get(table, {}).get(chain, 'ACCEPT'),
            'rules': [],
            'ignored_rules': [],
            'ignore': False,
        }

    iptables[table]['chains'][chain]['ignore'] = True

# generate ignored Rules
for rule in node.metadata.get('iptables', {}).get('ignored', {}).get('rules', []):
    table = rule.get('table', 'filter')

    # if we have no rules for this table, we skip this ignored rule
    if table not in iptables:
        continue

    chain = rule.pop('chain', 'INPUT')
    if chain not in iptables[table]['chains']:
        iptables[table]['chains'][chain] = {
            'policy': node.metadata.get('iptables', {}).get('policies', {}).get(table, {}).get(chain, 'ACCEPT'),
            'rules': [],
            'ignored_rules': [],
            'ignore': False,
        }
    iptables[table]['chains'][chain]['ignored_rules'] += [rule, ]

docs = {}
for table in iptables.keys():
    for chain_name in iptables[table]['chains'].keys():
        chain = iptables[table]['chains'][chain_name]
        policy = 'POLICY: {policy}'.format(policy=chain.get('policy', 'Not Set'))

        doc_rules_v4 = [policy, ]
        doc_rules_v6 = [policy, ]

        for rule in chain['rules']:
            r, v = repo.libs.iptables.generate_rule_for_docs(chain_name, rule)
            if v == IP_V4 or v == IP_V4_AND_6:
                doc_rules_v4.append(r)

            if v == IP_V6 or v == IP_V4_AND_6:
                doc_rules_v6.append(r)

        docs['iptables - {table}:{chain}'.format(table=table, chain=chain_name)] = {
            'type': 'list',
            'content': doc_rules_v4,
        }

        docs['ip6tables - {table}:{chain}'.format(table=table, chain=chain_name)] = {
            'type': 'list',
            'content': doc_rules_v6,
        }
