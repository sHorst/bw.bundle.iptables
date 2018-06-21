IPTables Modul
--------------

This module checks the METADATA for iptables rules and applies them. It ensures that the Rules are set after the apply.

Demo Metadata
-------------

```python
'iptables': {
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
def add_iptables_rule(metadata):
    if node.has_bundle("iptables"):
        interfaces = ['main_interface']
        interfaces += metadata.get('nginx', {}).get('additional_interfaces', [])

        for interface in interfaces:
            metadata += (repo.libs.iptables.accept()
                         .input(interface)
                         .state_new()
                         .tcp()
                         .dest_port('80'))

            metadata += (repo.libs.iptables.accept()
                         .input(interface)
                         .state_new()
                         .tcp()
                         .dest_port('443'))
        # ignore this chains
        
        metadata += repo.libs.iptables.jump('MY_CUSTOM_CHAIN').chain('FORWARD').ignore(),
        metadata += repo.libs.iptables.ignore_chain('FORWARD'),
        
    return metadata, True
```
