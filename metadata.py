defaults = {}

if node.has_bundle("apt"):
    defaults = {
        'apt': {
            'packages': {
                'iptables': {'installed': True},
            }
        }
    }

    if node.os == 'debian' and node.os_version[0] in (8, 9):
        defaults['apt']['packages']['xtables-addons-common'] = {'installed': True}
