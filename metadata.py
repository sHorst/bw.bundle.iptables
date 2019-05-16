@metadata_processor
def add_apt_packages(metadata):
    if node.has_bundle("apt"):
        metadata.setdefault('apt', {})
        metadata['apt'].setdefault('packages', {})

        metadata['apt']['packages']['iptables'] = {'installed': True}
        metadata['apt']['packages']['xtables-addons-common'] = {'installed': True}

    return metadata, DONE