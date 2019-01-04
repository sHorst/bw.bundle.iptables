from bundlewrap.items import Item, ItemStatus
from bundlewrap.exceptions import BundleError
from bundlewrap.utils.text import force_text, mark_for_translation as _
from bundlewrap.utils.remote import PathInfo
import types
from pipes import quote
from ipaddress import ip_network
import tempfile
import os
import socket
import re

IP_V4 = 4
IP_V6 = 6
IP_V4_AND_6 = 46

allowed_keys = {
    'source': '-s {}',
    'not_source': '! -s {}',
    'destination': '-d {}',
    'not_destination': '! -d {}',
    'input': '-i {}',
    'output': '-o {}',
    'protocol': '-p {}',
    'src_range': '-m iprange --src-range {}',
    'dest_range': '-m iprange --dst-range {}',
    'pkt_type': '-m pkttype --pkt_type {}',
    'state': '-m state --state {}',
    'tcp_dest_port': '-m tcp --dport {}',
    'tcp_src_port': '-m tcp --sport {}',
    'udp_dest_port': '-m udp --dport {}',
    'udp_src_port': '-m udp --sport {}',
    'dest_port_range': '-m multiport --dports {}',
    'src_port_range': '-m multiport --sports {}',
    'icmp-type': '-m icmp --icmp-type {}',
    'icmpv6-type': '-p icmpv6 --icmpv6-type {}',
    'mark': '-m mark --mark {}',
    'comment': '-m comment --comment {}',
    'custom': '{}',
    'jump': '-j {}',
}

DEFAULT_POLICIES = {
    'filter': {
        'INPUT': 'DROP',
        'FORWARD': 'DROP',
        'OUTPUT': 'DROP',
        'LOGDROP': '-',
    },
    'nat': {
        'PREROUTING': 'ACCEPT',
        'INPUT': 'ACCEPT',
        'OUTPUT': 'ACCEPT',
        'POSTROUTING': 'ACCEPT',
    },
    'mangle': {
        'PREROUTING': 'ACCEPT',
        'INPUT': 'ACCEPT',
        'FORWARD': 'ACCEPT',
        'OUTPUT': 'ACCEPT',
        'POSTROUTING': 'ACCEPT',
    },
}


def is_ignored_chain(line, chains):
    # check if line (regex itself) is in ignored chains
    if line in chains:
        return True

    # check regex against line
    for chain in chains:
        if re.search(r"{}".format(chain), line) is not None:
            return True

    # nothing found, so it is not ignored
    return False


def is_ignored_rule(line, chains, rules):
    for chain in chains:
        if re.search(r"^-A {}".format(chain), line) is not None:
            return True

    # check if all rules are containt in line
    for rule in rules:
        line_ignored_by_rule = True
        at_least_one_allowed_key = False
        for key in allowed_keys.keys():
            if key not in rule:
                continue

            at_least_one_allowed_key = True
            # if all of the keys in rule are contained in line
            pattern = r"{}".format(allowed_keys[key].format(rule[key]))
            if re.search(pattern, line) is None:
                line_ignored_by_rule = False

        if at_least_one_allowed_key and line_ignored_by_rule:
            return True

    return False


def generate_ignored_rules_and_chains(attributes):
    ignored_chains = []
    ignored_rules = []

    for chain_name in attributes.get('chains', {}).keys():
        chain = attributes['chains'][chain_name]
        if chain.get('ignore', False):
            ignored_chains += [chain_name, ]

        for rule in attributes['chains'][chain_name].get('ignored_rules', []):
            ignored_rules += [rule, ]

    return ignored_chains, ignored_rules


# we cannot include libs/iptables.py therefor we need to copy this code
def generate_rule(chain, config_dict_orig):
    # make copy since we change stuff
    config_dict = config_dict_orig.copy()

    version = config_dict.get('version', IP_V4_AND_6)

    # icmp Type is V4 only
    if 'icmp-type' in config_dict:
        version = IP_V4

    # icmpv6 Type is V6 only
    if 'icmpv6-type' in config_dict:
        version = IP_V6

    # we overwrite this, if src_range or dest_range is set
    if 'src_range' in config_dict or \
       'dest_range' in config_dict or \
       'source' in config_dict or \
       'destination' in config_dict:

        source = ip_network(config_dict['source']) if 'source' in config_dict else None
        destination = ip_network(config_dict['destination']) if 'destination' in config_dict else None
        src_range = ip_network(config_dict['src_range'].split('-')[0]) if 'src_range' in config_dict else None
        dest_range = ip_network(config_dict['dest_range'].split('-')[0]) if 'dest_range' in config_dict else None

        if source and src_range:
            raise BundleError(_(
                "Source and Source Range cannot be present at same time on {item} in bundle '{bundle}'"
            ).format(
                bundle=bundle.name,
                item=item_id,
            ))

        if destination and dest_range:
            raise BundleError(_(
                "Destination and Destination Range cannot be present at same time on {item} in bundle '{bundle}'"
            ).format(
                bundle=bundle.name,
                item=item_id,
            ))

        if (source and destination and source.version != destination.version) or \
           (source and dest_range and source.version != dest_range.version) or \
           (src_range and destination and src_range.version != destination.version) or \
           (src_range and dest_range and src_range.version != dest_range.version):

            raise BundleError(_(
                "Source IP Version must match Destination IP Version on {item} in bundle '{bundle}'"
            ).format(
                bundle=bundle.name,
                item=item_id,
            ))

        if source:
            version = source.version

            # unify output to 192.168.0.1/32
            config_dict['source'] = str(source)

        if destination:
            version = destination.version

            # unify output to 192.168.0.1/32
            config_dict['destination'] = str(destination)

        if src_range:
            version = src_range.version

        if dest_range:
            version = dest_range.version

    # generate rules from config_dict
    rule = []
    for key in allowed_keys.keys():
        if key not in config_dict:
            continue

        rule.append(allowed_keys[key].format(config_dict[key]))

    return "-A {chain} {rule}".format(chain=chain, rule=" ".join(rule)), version


def sorted_chains(table, chains):
    table_chains = list(DEFAULT_POLICIES.get(table, {}).keys())
    sorted_chains = [x for x in table_chains if x in chains]
    unsorded_chains = [x for x in chains if x not in table_chains]

    return sorted_chains + unsorded_chains


def generate_rules_and_chains(table, attributes):
    chains = []
    rules_v4 = []
    rules_v6 = []
    ignored_chains, ignored_rules = generate_ignored_rules_and_chains(attributes)

    for chain_name in sorted_chains(table, attributes.get('chains', {}).keys()):
        if is_ignored_chain(chain_name, ignored_chains):
            continue

        chain = attributes['chains'][chain_name]
        chains.append(':{chain} {policy}'.format(chain=chain_name, policy=chain.get('policy', '-')))

        for rule in chain.get('rules', []):
            r, v = generate_rule(chain_name, rule)

            # ignore Rules
            if is_ignored_rule(r, ignored_chains, ignored_rules):
                continue

            if v == IP_V4 or v == IP_V4_AND_6:
                rules_v4.append(r)

            if v == IP_V6 or v == IP_V4_AND_6:
                rules_v6.append(r)

    # chain_v4 and chain_v6 should be the same
    return chains, chains, rules_v4, rules_v6


def generate_tmp_file_iptables_save_restore(version=IP_V4):
    fn_save_restore = tempfile.NamedTemporaryFile(delete=False)

    iptables_restore = '/sbin/ip6tables-restore' if version == IP_V6 else '/sbin/iptables-restore'
    iptables_save = '/sbin/ip6tables-save' if version == IP_V6 else '/sbin/iptables-save'
    iptables_backup = '/tmp/ip6tables_old' if version == IP_V6 else '/tmp/iptables_old'
    iptables_confirm = '/tmp/ip6tables_confirm' if version == IP_V6 else '/tmp/iptables_confirm'

    # little hackie, we cannot use format, since bash contains {}. and mako is a little bit overblown
    fn_save_restore.write(("""#!/usr/bin/env bash

wait_file() {
  local file="$1"
  local wait_seconds="${2:-10}" # 10 seconds as default timeout

  until test $((wait_seconds--)) -eq 0 -o -f "$file" ; do sleep 1; done
  ((++wait_seconds))
}

iptables_safe_reload(){
    # get last parameter, since this is the filename
    iptables_rules="${@: -1}"

    # remove last parameter
    set -- "${@:1:$(($#-1))}"

    # remove confirmation file
    rm -f """ + iptables_confirm + """

    # save backup
    logger "Saving backup"
    """ + iptables_save + """ > """ + iptables_backup + """

    logger "Try Loading Tmp file"
    cat $iptables_rules | """ + iptables_restore + """ $@

    wait_file '""" + iptables_confirm + """' 60 || {
        logger "Timeout occured, restoring old ruleset"
        cat """ + iptables_backup + """ | """ + iptables_restore + """
        exit 1
    }

    logger "File appeared, clearing up"
    rm """ + iptables_confirm + """:w
    rm """ + iptables_backup + """
    exit 0
}

# detach from stdin, stdout and stderr, so ssh can exit savely
exec 1>&-
exec 2>&-
exec 0<&-

(iptables_safe_reload $@)&
    """).encode('utf-8'))
    fn_save_restore.close()

    return fn_save_restore


def generate_tmp_file_rules(table, chains, rules):
    fn = tempfile.NamedTemporaryFile(delete=False)

    fn.write(b"# Generated by bundlewrap\n")
    fn.write("*{table}\n".format(table=table).encode('utf-8'))
    fn.write("{chains}\n".format(chains="\n".join(chains)).encode('utf-8'))
    fn.write("{rules}\n".format(rules="\n".join(rules)).encode('utf-8'))
    fn.write(b"COMMIT\n")
    fn.write(b"# Completed\n")

    fn.close()

    return fn


class IptablesTable(Item):
    """
    Generate IPTables Rules.
    """

    BUNDLE_ATTRIBUTE_NAME = "iptables"
    NEEDS_STATIC = [
        "pkg_apt:",
        "pkg_pacman:",
        "pkg_yum:",
        "pkg_zypper:",
    ]
    ITEM_ATTRIBUTES = {
        'chains': {},
        'check': True,
        'check_port': 22,
    }
    ITEM_TYPE_NAME = "iptable"
    REQUIRED_ATTRIBUTES = []

    def __repr__(self):
        return "<iptables chain:{}>".format(self.name)

    def preview(self):
        # generate chains and rules from attributes
        chain_v4, chain_v6, rules_v4, rules_v6 = generate_rules_and_chains(self.name, self.attributes)

        output = "# Generated by bundlewrap\n"
        output += "*{table}\n".format(table=self.name)
        output += "{chains}\n".format(chains="\n".join(chain_v4))
        output += "{rules}\n".format(rules="\n".join(rules_v4))
        output += "{chains}\n".format(chains="\n".join(chain_v6))
        output += "{rules}\n".format(rules="\n".join(rules_v6))
        output += "COMMIT\n"
        output += "# Completed\n"

        print(self.attributes)

        return output

    def fix(self, status):
        # generate chains and rules from attributes
        chain_v4, chain_v6, rules_v4, rules_v6 = generate_rules_and_chains(self.name, self.attributes)

        # generate local tmp files
        fn_save_restore_v4 = generate_tmp_file_iptables_save_restore(IP_V4)
        fn_save_restore_v6 = generate_tmp_file_iptables_save_restore(IP_V6)
        fn_v4 = generate_tmp_file_rules(self.name, chain_v4, rules_v4)
        fn_v6 = generate_tmp_file_rules(self.name, chain_v6, rules_v6)

        # upload files to node
        self.node.upload(fn_save_restore_v4.name, '/tmp/iptables-restore-save', '700', 'root', 'root')
        self.node.upload(fn_save_restore_v6.name, '/tmp/ip6tables-restore-save', '700', 'root', 'root')

        self.node.upload(fn_v4.name, '/tmp/iptables.{}.rules'.format(self.name), '600', 'root', 'root')
        self.node.upload(fn_v6.name, '/tmp/ip6tables.{}.rules'.format(self.name), '600', 'root', 'root')

        # delete the temp files
        os.unlink(fn_v4.name)
        os.unlink(fn_v6.name)
        os.unlink(fn_save_restore_v4.name)
        os.unlink(fn_save_restore_v6.name)

        # test if rules are syntactically correct
        self.node.run(
            "/sbin/iptables-restore -t -T {table} /tmp/iptables.{table}.rules".format(table=self.name),
            log_output=True
        )
        self.node.run(
            "/sbin/ip6tables-restore -t -T {table} /tmp/ip6tables.{table}.rules".format(table=self.name),
            log_output=True
        )

        self.node.run("/tmp/iptables-restore-save -T {table} /tmp/iptables.{table}.rules".format(table=self.name))
        self.node.run("/tmp/ip6tables-restore-save -T {table} /tmp/ip6tables.{table}.rules".format(table=self.name))

        if self.attributes.get('check', True):
            # check if ssh port is open
            check_port = self.attributes.get('check_port', 22)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((self.node.hostname, check_port))
            if result != 0:
                raise BundleError(_(
                    "iptables broke connection to {port}. Waiting for reset (60s)."
                ).format(
                    port=check_port,
                ))

        self.node.run("touch /tmp/iptables_confirm")
        self.node.run("touch /tmp/ip6tables_confirm")

        # write actual iptables output to /etc/network
        self.node.run("iptables-save -t {table} > /etc/network/iptables.{table}.rules".format(table=self.name))
        self.node.run("ip6tables-save -t {table} > /etc/network/ip6tables.{table}.rules".format(table=self.name))

    # should look like this
    def cdict(self):
        table = self.name

        chains_v4, chains_v6, rules_v4, rules_v6 = generate_rules_and_chains(self.name, self.attributes)

        # the order of the chains is ignored
        cdict = {
            'type': 'iptables',
            'table': table,
            'chains_v4': sorted(chains_v4),
            'chains_v6': sorted(chains_v6),
            'rules_v4': rules_v4,
            'rules_v6': rules_v6,
        }

        return cdict

    # real world
    def sdict(self):
        table = self.name
        ignored_chains, ignored_rules = generate_ignored_rules_and_chains(self.attributes)

        res = self.node.run("iptables-save -t {table}".format(table=table), may_fail=True)
        ip4tables = res.stdout.decode('utf-8').strip()

        chains_v4 = []
        rules_v4 = []
        for line in ip4tables.split('\n'):
            # lines starting with : are CHAINS
            if line[0] == ":":
                chain = line[1:].split(' ')[0]
                policy = line[1:].split(' ')[1]

                if is_ignored_chain(chain, ignored_chains):
                    continue

                # drop counter from output
                chains_v4.append(":{chain} {policy}".format(chain=chain, policy=policy))

            if line[0:3] == "-A ":
                # if it does not exists, the iptables-save output is broken
                if not is_ignored_rule(line, ignored_chains, ignored_rules):
                    rules_v4.append(line)

        res = self.node.run("ip6tables-save -t {table}".format(table=table), may_fail=True)
        ip6tables = res.stdout.decode('utf-8').strip()

        # the order of the chains is ignored
        chains_v6 = []
        rules_v6 = []
        for line in ip6tables.split('\n'):
            # lines starting with : are CHAINS
            if line[0] == ":":
                chain = line[1:].split(' ')[0]
                policy = line[1:].split(' ')[1]

                if is_ignored_chain(chain, ignored_chains):
                    continue

                # drop counter from output
                chains_v6.append(":{chain} {policy}".format(chain=chain, policy=policy))

            if line[0:3] == "-A ":
                # if it does not exists, the iptables-save output is broken

                if not is_ignored_rule(line, ignored_chains, ignored_rules):
                    rules_v6.append(line)

        sdict = {
            'type': 'iptables',
            'table': table,
            'chains_v4': sorted(chains_v4),
            'chains_v6': sorted(chains_v6),
            'rules_v4': rules_v4,
            'rules_v6': rules_v6,
        }

        return sdict

    @classmethod
    def validate_attributes(cls, bundle, item_id, attributes):
        if item_id[len(cls.ITEM_TYPE_NAME) + 1:] not in ['filter', 'mangle', 'nat']:
            raise BundleError(_(
                "table '{table}' is not allowed {item} in bundle '{bundle}'"
            ).format(
                bundle=bundle.name,
                item=item_id,
                table=item_id[len(bundle.name) + 1:],
            ))

        if not attributes.get('chains', None):
            raise BundleError(_(
                "chains must be set on {item} in bundle '{bundle}'"
            ).format(
                bundle=bundle.name,
                item=item_id,
            ))
        # TODO: check if rules are allowed and valid

    def patch_attributes(self, attributes):
        if 'chains' in attributes:
            for chain in DEFAULT_POLICIES.get(self.name, {}).keys():
                if chain not in attributes['chains'].keys():
                    attributes['chains'][chain] = {
                        'policy': DEFAULT_POLICIES[self.name][chain],
                        'rules': [],
                    }

        return attributes

    @classmethod
    def get_auto_deps(cls, items):
        deps = []
        for item in items:
            # debian TODO: add other package manager
            if item.ITEM_TYPE_NAME == 'pkg_apt' and item.name == 'iptables':
                deps.append(item.id)
        return deps
