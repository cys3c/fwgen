#!/usr/bin/env python3

import argparse
import sys
import re
import subprocess

import yaml


DEFAULT_CHAINS_IP = {
    'filter': ['INPUT', 'FORWARD', 'OUTPUT'],
    'nat': ['PREROUTING', 'INPUT', 'OUTPUT', 'POSTROUTING'],
    'mangle': ['PREROUTING', 'INPUT', 'FORWARD', 'OUTPUT', 'POSTROUTING'],
    'raw': ['PREROUTING', 'OUTPUT'],
    'security': ['INPUT', 'FORWARD', 'OUTPUT']
}
DEFAULT_CHAINS_IP6 = DEFAULT_CHAINS_IP
CONFIG = '/etc/fwgen/config.yml'
IPTABLES_SAVE = '/etc/iptables.restore'
IP6TABLES_SAVE = '/etc/ip6tables.restore'


class FwGen(object):
    def __init__(self, config):
        self.config = config
        self.default_chains = {
            'ip': DEFAULT_CHAINS_IP,
            'ip6': DEFAULT_CHAINS_IP6
        }

    def get_policy_rules(self, family):
        for table, chains in self.default_chains[family].items():
            for chain in chains:
                try:
                    policy = self.config['policies'][family][table][chain]
                except KeyError:
                    policy = 'ACCEPT'
                yield (table, ':%s %s' % (chain, policy))

    def get_zone_rules(self, family):
        for zone, params in self.config['zones'].items():
            try:
                for table, chains in params['rules'][family].items():
                    for chain, chain_rules in chains.items():
                        zone_chain = '%s_%s' % (zone, chain)
                        for rule in chain_rules:
                            yield (table, '-A %s %s' % (zone_chain, rule))
            except KeyError:
                continue

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
        for zone, params in self.config['zones'].items():
            try:
                for table, chains in params['rules'][family].items():
                    for chain in chains:
                        dispatcher_chain = '%s_%s' % (zone, chain)
                        yield self.get_new_chain_rule(table, dispatcher_chain)

                        if chain in ['PREROUTING', 'INPUT', 'FORWARD']:
                            yield (table, '-A %s -i %%{%s} -j %s' % (chain, zone, dispatcher_chain))
                        elif chain in ['OUTPUT', 'POSTROUTING']:
                            yield (table, '-A %s -o %%{%s} -j %s' % (chain, zone, dispatcher_chain))
                        else:
                            raise Exception('%s is not a valid default chain' % chain)
            except KeyError:
                continue

    def expand_zones(self, rule):
        zone_pattern = re.compile(r'^(.+?\s)%\{(.+?)\}(\s.+)$')
        match = re.search(zone_pattern, rule)

        if match:
            zone = match.group(2)

            for interface in self.config['zones'][zone]['interfaces']:
                rule_expanded = '%s%s%s' % (match.group(1), interface, match.group(3))
                yield from self.expand_zones(rule_expanded)
        else:
            yield rule

    def output_rules(self, rules, family):
        for table in self.default_chains[family]:
            yield '*%s' % table

            for rule_table, rule in rules:
                if rule_table == table:
                    yield from self.expand_zones(rule)

            yield 'COMMIT'

    @staticmethod
    def save_rules(path, family):
        cmd = {
            'ip': ['iptables-save'],
            'ip6': ['ip6tables-save']
        }

        with open(path, 'wb') as f:
            subprocess.run(cmd[family], stdout=f)

    def save(self):
        save = {
            'ip': IPTABLES_SAVE,
            'ip6': IP6TABLES_SAVE
        }

        for family in ['ip', 'ip6']:
            self.save_rules(save[family], family)

    @staticmethod
    def apply_rules(rules, family):
        cmd = {
            'ip': ['iptables-restore'],
            'ip6': ['ip6tables-restore']
        }
        stdin = ('%s\n' % '\n'.join(rules)).encode('utf-8')
        subprocess.run(cmd[family], input=stdin)

    def apply(self):
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

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', metavar='PATH', help='Path to config file')
    args = parser.parse_args()

    config_yaml = CONFIG
    if args.config:
        config_yaml = args.config

    with open(config_yaml, 'r') as f:
        config = yaml.load(f)

    fw = FwGen(config)
    fw.commit()

if __name__ == '__main__':
    sys.exit(main())
