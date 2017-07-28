# Introduction
fwgen is a small management framework to simplify the management of ip(6)tables based firewalls, that also integrates ipset support and zones in a non-restrictive way. It is *not* an abstraction layer of the iptables syntax, so you still need to understand how to write iptables rules and how packets are processed through the iptables chains. This is the intended project scope to ensure all existing functionality is made available. fwgen does however help you create an efficient ruleset with very little effort.

fwgen is mainly targeted towards network gateways and hosts which are configured via configuration management systems, often with multiple interfaces and complex rulesets that very fast gets unmanagable or inefficient if not done right. It may not be worth the effort to install it if you just have a simple server where you want to allow a couple of incoming ports.

Advantages of using fwgen:
* Integrates iptables, ip6tables and ipsets in a common management framework
* Uses a simple config file in YAML format for easy and readable configuration
* Separation of duties between the loading of firewall rules at boot/ifup (restore-fw) and the rule generation (fwgen). No complex code are executed during boot/ifup.
* Firewall operations are atomic. It either applies correctly or not, without flushing your existing ruleset, potentially leaving you temporarily exposed. However, ipsets are currently flushed for a very short period to enforce concistency with your configuration.
* Automatic rollback to previous ruleset if not confirmed when applying rulesets in case something goes wrong. This can be disabled if run automatically by configuration management systems etc.
* Namespace support. If executed in a namespace it automatically stores the rulesets in `/etc/netns/<namespace>/` instead of in the global namespace.

# Requirements
* At least Python 3.5
* PyYAML
* ipset

# Installation
## Debian Stretch
Install the requirements:

    apt-get install ipset python3-yaml

Put the files someplace logical. fwgen by default looks in `/etc/fwgen/` for configuration files. As the configuration files contains the ruleset access should be restricted.

    mkdir /etc/fwgen
    cp defaults.yml /etc/fwgen/
    touch /etc/fwgen/config.yml
    chown -R root. /etc/fwgen
    chmod 600 /etc/fwgen/*.yml

    cp fwgen.py /usr/local/bin/fwgen
    cp restore-fw.sh /usr/local/bin/restore-fw
    ln -s /usr/local/bin/restore-fw /etc/network/if-pre-up.d/restore-fw

# Usage
Edit `/etc/fwgen/config.yml`. Look at the [example configuration](src/config.yml.example) for guidance.

To generate the new ruleset:

    fwgen

To skip confirmation:

    fwgen --no-confirm

If ipsets in use causes issues with applying the new ruleset:

    fwgen --with-reset
