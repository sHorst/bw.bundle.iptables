from ipaddress import ip_network

IP_V4 = 4
IP_V6 = 6
IP_V4_AND_6 = 46

allowed_keys = {
    'source': '-s {}',
    'not_source': '! -s {}',
    'destination': '-d {}',
    'not_destination': '! -d {}',
    'input': '-i {}',
    'not_input': '! -i {}',
    'output': '-o {}',
    'not_output': '! -o {}',
    'protocol': '-p {}',
    'src_range': '-m iprange --src-range {}',
    'dest_range': '-m iprange --dst-range {}',
    'pkt_type': '-m pkttype --pkt-type {}',
    'state': '-m state --state {}',
    'ctstate': '-m conntrack --ctstate {}',
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


# we cannot include libs/iptables.py in items/iptables.py therefor we need to copy this code
def generate_rule_for_docs(chain, config_dict_orig):
    # make copy since we change stuff
    config_dict = config_dict_orig.copy()

    version = config_dict.get('version', IP_V4_AND_6)

    # icmp Type is V4 only
    if 'icmp-type' in config_dict:
        version = IP_V4

    # icmpv6 Type is V6 only
    if 'icmpv6-type' in config_dict:
        version = IP_V6

    # we overwrite this, if source or destination is set
    if 'source' in config_dict or 'destination' in config_dict:
        source = ip_network(config_dict['source']) if 'source' in config_dict else None
        destination = ip_network(config_dict['destination']) if 'destination' in config_dict else None

        if source and destination and source.version != destination.version:
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

    # generate rules from config_dict
    rule = []
    for key in allowed_keys.keys():
        if key not in config_dict:
            continue

        rule.append(allowed_keys[key].format(config_dict[key]))

    return "-A {chain} {rule}".format(chain=chain, rule=" ".join(rule)), version


def accept():
    return IptablesRule(jump='ACCEPT')


def drop():
    return IptablesRule(jump='DROP')


def log():
    return IptablesRule(jump='LOG')


def jump(jump):
    return IptablesRule(jump=jump)


def snat(source):
    return IptablesRule(jump='SNAT --to-source {}'.format(source))


def dnat(destination):
    return IptablesRule(jump='DNAT --to-destination {}'.format(destination))


def mark(mark_id):
    return IptablesRule(jump='MARK --set-mark {mark}'.format(mark=mark_id))


def masquerade():
    return IptablesRule(jump='MASQUERADE')


def redirect(ports):
    return IptablesRule(jump='REDIRECT --to-ports {ports}'.format(ports=ports))


def ignore_chain(chain):
    return IptablesRule().chain(chain).ignore_chain()


def count():
    return IptablesRule()


def convert_to_iptables_rule(old):
    if isinstance(old, IptablesRule):
        return old
    new = IptablesRule()

    for key, value in old.items():
        new[key] = value

    return new


class IptablesRule(dict):
    """Interface for building iptables rules easily"""
    def __init__(self, jump=None):
        super().__init__()
        self.is_ignore = False
        self.is_ignore_chain = False
        self.prio_value = 50

        if isinstance(jump, dict):
            for k, v in jump.items():
                self[k] = v
        else:
            if jump is not None:
                self['jump'] = jump

    # table
    def table(self, table):
        self['table'] = table
        return self

    # chain
    def chain(self, chain):
        self['chain'] = chain
        return self

    # jump
    def jump(self, jump):
        self['jump'] = jump
        return self

    def accept(self):
        return self.jump('ACCEPT')

    def drop(self):
        return self.jump('DROP')

    def reject(self):
        return self.jump('REJECT')

    # input
    def input(self, input_interface, negate=False):
        if negate:
            self['not_input'] = input_interface
        else:
            self['input'] = input_interface
        return self

    # output
    def output(self, output_interface, negate=False):
        if negate:
            self['not_output'] = output_interface
        else:
            self['output'] = output_interface
        return self

    # source
    def source(self, source, negate=False):
        if negate:
            self['not_source'] = source
        else:
            self['source'] = source
        return self

    # destination
    def destination(self, destination, negate=False):
        if negate:
            self['not_destination'] = destination
        else:
            self['destination'] = destination
        return self

    def src_range(self, src_range):
        self['src_range'] = src_range
        return self

    def dest_range(self, dest_range):
        self['dest_range'] = dest_range
        return self

    # state
    def state(self, state):
        self['state'] = state
        return self

    # state
    def ctstate(self, state):
        self['ctstate'] = state
        return self

    def state_new(self):
        return self.state('NEW')

    # pkt_type
    def pkt_type(self, pkt_type):
        self['pkt_type'] = pkt_type
        return self

    def multicast(self):
        return self.pkt_type('multicast')

    # protocol
    def protocol(self, protocol):
        self['protocol'] = protocol

        return self

    def tcp(self):
        return self.protocol('tcp')

    def udp(self):
        return self.protocol('udp')

    def icmp(self):
        return self.protocol('icmp')

    def esp(self):
        return self.protocol('esp')

    # port
    def dest_port(self, port):
        protocol = self.get('protocol', 'tcp')
        if protocol == 'tcp':
            self['tcp_dest_port'] = port
        elif protocol == 'udp':
            self['udp_dest_port'] = port

        return self

    def src_port(self, port):
        protocol = self.get('protocol', 'tcp')
        if protocol == 'tcp':
            self['tcp_src_port'] = port
        elif protocol == 'udp':
            self['udp_src_port'] = port

        return self

    def dest_port_range(self, start_port, end_port):
        self['dest_port_range'] = "{}:{}".format(start_port, end_port)

        return self

    def src_port_range(self, start_port, end_port):
        self['src_port_range'] = "{}:{}".format(start_port, end_port)

        return self

    def get_mark(self, mark_id):
        self['mark'] = mark_id
        return self

    def version(self, version):
        self['version'] = int(version)
        return self

    # custom
    def custom(self, custom):
        self['custom'] = custom

        return self

    def comment(self, comment):
        self['comment'] = comment

        return self

    def ignore(self):
        self.is_ignore = True

        return self

    def ignore_chain(self):
        self.is_ignore = True
        self.is_ignore_chain = True

        return self

    def prio(self, prio):
        self.prio_value = prio

        return self

    # add to Metadata
    def __radd__(self, metadata):
        if 'iptables' not in metadata:
            metadata['iptables'] = {}

        if self.is_ignore:
            if 'ignored' not in metadata['iptables']:
                metadata['iptables']['ignored'] = {}

            if self.is_ignore_chain:
                if 'chains' not in metadata['iptables']['ignored']:
                    metadata['iptables']['ignored']['chains'] = []

                metadata['iptables']['ignored']['chains'].append(
                    {
                        'table': self.get('table', 'filter'),
                        'chain': self['chain'],  # this will throw an exeption, if mandatory chain is not set!
                    }
                )
            else:
                if 'rules' not in metadata['iptables']['ignored']:
                    metadata['iptables']['ignored']['rules'] = []

                metadata['iptables']['ignored']['rules'].append(self)
        else:
            if 'rules' not in metadata['iptables']:
                metadata['iptables']['rules'] = []

            metadata['iptables']['rules'].append(self)

        return metadata
    
    def __lt__(self, other):
        if isinstance(other, IptablesRule):
            if self.prio_value != other.prio_value:
                return self.prio_value < other.prio_value
            if self.get('chain', 'INPUT') != other.get('chain', 'INPUT'):
                return self.get('chain', 'INPUT') < other.get('chain', 'INPUT')

            # order by dest Port
            my_port = str(self.get('tcp_dest_port', self.get('udp_dest_port', 99999)))
            other_port = str(other.get('tcp_dest_port', other.get('udp_dest_port', 99999)))

            if my_port != other_port:
                # handle ports like 8000:8001
                if not my_port.isdigit():
                    my_port = '99999'

                if not other_port.isdigit():
                    other_port = '99999'

                return int(my_port) < int(other_port)

            # order by protocol
            if self.get('protocol', 'tcp') != other.get('protocol', 'tcp'):
                return self.get('protocol', 'tcp') < other.get('protocol', 'tcp')

            # order by input
            if self.get('input', 'eth0') != other.get('input', 'eth0'):
                return self.get('input', 'eth0') < other.get('input', 'eth0')

            return False
        else:
            return False
