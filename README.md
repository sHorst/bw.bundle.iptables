IPTables Modul
--------------

This module checks the METADATA for iptables rules and applies them. It ensures that the Rules are set after the apply.

Install
-------

To make this bundle work, you need to insert the libs/iptables.py and items/iptables.py to the bw repository. This can be done with this command:

```
ln -s ../bundles/iptables/libs/iptables.py libs/iptables.py
ln -s ../bundles/iptables/items/iptables.py items/iptables.py
```

Dependencies
------------
Packages defined in ```metadata.py``` and installed via [apt-Bundle](https://github.com/sHorst/bw.bundle.apt).

Demo Metadata
-------------

```python
'iptables': {
    'check': True,  # these are optional
    'check_port': 22,  # and default to the configured SSH port
    'policies': {
        'filter': {
            'INPUT': 'DROP',
            'OUTPUT': 'DROP',
            'FORWARD': 'DROP',
        }
    },
    'rules': [
        {'chain': 'INPUT', 'table': 'filter', 'input': 'eth0', 'port': '80', 'jump': 'ACCEPT'},
        {'chain': 'INPUT', 'table': 'filter', 'input': 'eth0', 'port': '443', 'jump': 'ACCEPT'},
    ],
    'ignored': {
        'chains': [
            {'table': 'filter', 'chain': 'MY_CUSTOM_CHAIN'},
        ],
        'rules': [
            {'chain': 'FORWARD', 'table': 'filter', 'jump': 'MY_CUSTOM_CHAIN'},
        ]
    }
},
```

If you want to add the metadata in another bundle you can use a metadata processor:

```python
@metadata_reactor
def add_iptables_rule(metadata):
    iptables_rules = {}
    if node.has_bundle("iptables"):
        interfaces = ['main_interface']
        interfaces += metadata.get('nginx', {}).get('additional_interfaces', [])

        for interface in interfaces:
            metaiptables_rulesdata += (repo.libs.iptables.accept()
                         .input(interface)
                         .state_new()
                         .tcp()
                         .dest_port('80'))

            iptables_rules += (repo.libs.iptables.accept()
                         .input(interface)
                         .state_new()
                         .tcp()
                         .dest_port('443'))
        # ignore this chains
        
        iptables_rules += repo.libs.iptables.jump('MY_CUSTOM_CHAIN').chain('FORWARD').ignore(),
        iptables_rules += repo.libs.iptables.ignore_chain('FORWARD'),
        
    return iptables_rules
```
