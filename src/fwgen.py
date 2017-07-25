#!/usr/bin/env python3

import argparse
import sys
import re
import subprocess
import os
import signal
from collections import OrderedDict

import yaml


DEFAULT_CHAINS_IP = {
    'filter': ['INPUT', 'FORWARD', 'OUTPUT'],
    'nat': ['PREROUTING', 'INPUT', 'OUTPUT', 'POSTROUTING'],
    'mangle': ['PREROUTING', 'INPUT', 'FORWARD', 'OUTPUT', 'POSTROUTING'],
    'raw': ['PREROUTING', 'OUTPUT'],
    'security': ['INPUT', 'FORWARD', 'OUTPUT']
}
DEFAULT_CHAINS_IP6 = DEFAULT_CHAINS_IP
CONFIG = b'/etc/fwgen/config.yml'
DEFAULTS = b'/etc/fwgen/defaults.yml'
TIMEOUT=30


class FwGen(object):
    def __init__(self, config):
        self.config = config
        self.default_chains = {
            'ip': DEFAULT_CHAINS_IP,
            'ip6': DEFAULT_CHAINS_IP6
        }

        etc = b'/etc'
        netns = self.get_netns()

        if netns:
            etc = b'/etc/netns/%s' % netns
            os.makedirs(etc, exist_ok=True)

        self.restore_file = {
            'ip': b'%s/iptables.restore' % etc,
            'ip6': b'%s/ip6tables.restore' % etc,
            'ipset': b'%s/ipsets.restore' % etc
        }
        self.restore_cmd = {
            'ip': ['iptables-restore'],
            'ip6': ['ip6tables-restore'],
            'ipset': ['ipset', 'restore']
        }
        self.save_cmd = {
            'ip': ['iptables-save'],
            'ip6': ['ip6tables-save']
        }

    @staticmethod
    def get_netns():
        output = subprocess.run(['ip', 'netns', 'identify'], stdout=subprocess.PIPE, check=True)
        return output.stdout.strip()

    def output_ipsets(self, reset=False):
        if reset:
            yield 'flush'
            yield 'destroy'
        else:
            for ipset, params in self.config.get('ipsets', {}).items():
                create_cmd = ['-exist create %s %s' % (ipset, params['type'])]
                create_cmd.append(params.get('options', None))
                yield ' '.join([i for i in create_cmd if i])
                yield 'flush %s' % ipset

                for entry in params['entries']:
                    yield 'add %s %s' % (ipset, entry)

    def get_policy_rules(self, family, reset=False):
        for table, chains in self.default_chains[family].items():
            for chain in chains:
                policy = 'ACCEPT'

                if not reset:
                    try:
                        policy = self.config['policies'][family][table][chain]
                    except KeyError:
                        pass

                yield (table, ':%s %s' % (chain, policy))

    def get_zone_rules(self, family):
        for zone, params in self.config.get('zones', {}).items():
            if 'rules' not in params:
                continue

            for table, chains in params['rules'].get(family, {}).items():
                for chain, chain_rules in chains.items():
                    zone_chain = '%s_%s' % (zone, chain)
                    for rule in chain_rules:
                        yield (table, '-A %s %s' % (zone_chain, rule))

    def get_default_rules(self, family):
        try:
            rules = self.config['defaults']['rules'][family]
        except KeyError:
            rules = {}
        return self.get_rules(rules)

    def get_helper_chains(self, family):
        try:
            rules = self.config['helper_chains'][family]
        except KeyError:
            rules = {}

        for table, chains in rules.items():
            for chain in chains:
                yield self.get_new_chain_rule(table, chain)

        yield from self.get_rules(rules)

    @staticmethod
    def get_rules(rules):
        for table, chains in rules.items():
            for chain, chain_rules in chains.items():
                for rule in chain_rules:
                    yield (table, '-A %s %s' % (chain, rule))

    @staticmethod
    def get_new_chain_rule(table, chain):
        return (table, ':%s -' % chain)

    def get_zone_dispatchers(self, family):
        for zone, params in self.config.get('zones', {}).items():
            if 'rules' not in params:
                continue

            for table, chains in params['rules'].get(family, {}).items():
                for chain in chains:
                    dispatcher_chain = '%s_%s' % (zone, chain)
                    yield self.get_new_chain_rule(table, dispatcher_chain)

                    if chain in ['PREROUTING', 'INPUT', 'FORWARD']:
                        yield (table, '-A %s -i %%{%s} -j %s' % (chain, zone, dispatcher_chain))
                    elif chain in ['OUTPUT', 'POSTROUTING']:
                        yield (table, '-A %s -o %%{%s} -j %s' % (chain, zone, dispatcher_chain))
                    else:
                        raise Exception('%s is not a valid default chain' % chain)

    def expand_zones(self, rule):
        zone_pattern = re.compile(r'^(.*?)%\{(.+?)\}(.*)$')
        match = re.search(zone_pattern, rule)

        if match:
            zone = match.group(2)

            for interface in self.config['zones'][zone]['interfaces']:
                rule_expanded = '%s%s%s' % (match.group(1), interface, match.group(3))
                yield from self.expand_zones(rule_expanded)
        else:
            yield rule

    def substitute_variables(self, rule):
        variable_pattern = re.compile(r'^(.*?)\$\{(.+?)\}(.*)$')
        match = re.search(variable_pattern, rule)

        if match:
            variable = match.group(2)
            value = self.config['variables'][variable]
            result = '%s%s%s' % (match.group(1), value, match.group(3))
            return self.substitute_variables(result)
        else:
            return rule

    def parse_rule(self, rule):
        rule = self.substitute_variables(rule)
        yield from self.expand_zones(rule)

    def output_rules(self, rules, family):
        for table in self.default_chains[family]:
            yield '*%s' % table

            for rule_table, rule in rules:
                if rule_table == table:
                    yield from self.parse_rule(rule)

            yield 'COMMIT'

    def save_ipsets(self, path):
        """
        Avoid using `ipset save` in case there are other
        ipsets used on the system for other purposes. Also
        this avoid storing now unused ipsets from previous
        configurations.
        """
        with open(path, 'w') as f:
            for item in self.output_ipsets():
                f.write('%s\n' % item)

    def save_rules(self, path, family):
        with open(path, 'wb') as f:
            subprocess.run(self.save_cmd[family], stdout=f, check=True)

    def save(self):
        for family in ['ip', 'ip6']:
            self.save_rules(self.restore_file[family], family)

        self.save_ipsets(self.restore_file['ipset'])

    def apply_rules(self, rules, family):
        stdin = ('%s\n' % '\n'.join(rules)).encode('utf-8')
        subprocess.run(self.restore_cmd[family], input=stdin, check=True)

    def restore_rules(self, path, family):
        with open(path, 'rb') as f:
            subprocess.run(self.restore_cmd[family], stdin=f, check=True)

    def apply_ipsets(self, ipsets):
        stdin = ('%s\n' % '\n'.join(ipsets)).encode('utf-8')
        subprocess.run(self.restore_cmd['ipset'], input=stdin, check=True)

    def restore_ipsets(self, path):
        with open(path, 'rb') as f:
            subprocess.run(self.restore_cmd['ipset'], stdin=f, check=True)

    def apply(self):
        # Apply ipsets first to ensure they exist when the rules are applied
        self.apply_ipsets(self.output_ipsets())

        for family in ['ip', 'ip6']:
            rules = []
            rules.extend(self.get_policy_rules(family))
            rules.extend(self.get_default_rules(family))
            rules.extend(self.get_helper_chains(family))
            rules.extend(self.get_zone_dispatchers(family))
            rules.extend(self.get_zone_rules(family))
            self.apply_rules(self.output_rules(rules, family), family)

    def commit(self):
        self.apply()
        self.save()

    def rollback(self):
        for family in ['ip', 'ip6']:
            if os.path.exists(self.restore_file[family]):
                self.restore_rules(self.restore_file[family], family)
            else:
                self.reset(family)

        if os.path.exists(self.restore_file['ipset']):
            self.restore_ipsets(self.restore_file['ipset'])
        else:
            self.apply_ipsets(self.output_ipsets(reset=True))

    def reset(self, family=None):
        families = ['ip', 'ip6']

        if family:
            families = [family]

        for family in families:
            rules = []
            rules.extend(self.get_policy_rules(family, reset=True))
            self.apply_rules(self.output_rules(rules, family), family)

        # Reset ipsets after the rules are removed to ensure ipsets are not in use
        self.apply_ipsets(self.output_ipsets(reset=True))


class TimeoutExpired(Exception):
    pass

def alarm_handler(signum, frame):
    raise TimeoutExpired

def wait_for_input(message, timeout):
    signal.signal(signal.SIGALRM, alarm_handler)
    signal.alarm(timeout)

    try:
        return input(message)
    finally:
        # Cancel alarm
        signal.alarm(0)

def dict_merge(d1, d2):
    """
    Deep merge d1 into d2
    """
    for k, v in d1.items():
        if isinstance(v, dict):
            node = d2.setdefault(k, {})
            dict_merge(v, node)
        else:
            d2[k] = v

    return d2

def setup_yaml():
    """
    Use to preserve dict order from imported yaml config
    """
    represent_dict_order = lambda self, data: self.represent_mapping('tag:yaml.org,2002:map',
                                                                      data.items())
    yaml.add_representer(OrderedDict, represent_dict_order)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', metavar='PATH', help='Path to config file')
    parser.add_argument('--with-reset', action='store_true',
        help='Clear the firewall before reapplying. Recommended only if ipsets in '
             'use are preventing you from applying the new configuration.')
    parser.add_argument('--no-confirm', action='store_true',
        help="Don't ask for confirmation before storing ruleset.")
    args = parser.parse_args()

    user_config = CONFIG
    if args.config:
        user_config = args.config

    setup_yaml()
    with open(DEFAULTS, 'r') as f:
        config = yaml.load(f)
    with open(user_config, 'r') as f:
        config = dict_merge(yaml.load(f), config)

    fw = FwGen(config)
    if args.with_reset:
        fw.reset()
    if args.no_confirm:
        fw.commit()
    else:
        print('\nRolling back in %d seconds if not confirmed.\n' % TIMEOUT)
        fw.apply()
        message = ('The ruleset has been applied successfully! Press \'Enter\' to make the '
                   'new ruleset persistent.\n')

        try:
            wait_for_input(message, TIMEOUT)
            fw.save()
        except (TimeoutExpired, KeyboardInterrupt):
            print('No confirmation received. Rolling back...\n')
            fw.rollback()

if __name__ == '__main__':
    sys.exit(main())
