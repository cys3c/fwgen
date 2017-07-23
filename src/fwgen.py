#!/usr/bin/env python3

import argparse
import sys
import re

import yaml


VALID_CHAINS = {
    'filter': ['INPUT', 'FORWARD', 'OUTPUT'],
    'nat': ['PREROUTING', 'INPUT', 'OUTPUT', 'POSTROUTING'],
    'mangle': ['PREROUTING', 'INPUT', 'FORWARD', 'OUTPUT', 'POSTROUTING'],
    'raw': ['PREROUTING', 'OUTPUT'],
    'security': ['INPUT', 'FORWARD', 'OUTPUT']
}


class FwGen(object):
    def __init__(self, config):
        self.config = config

    def get_policy_rules(self, inet_family):
        try:
            rules = self.config['policies'][inet_family]
        except KeyError:
            rules = {}

        for table, chains in rules.items():
            for chain, policy in chains.items():
                yield (table, ':%s %s' % (chain, policy))

    def get_zone_rules(self, inet_family):
        for zone, params in self.config['zones'].items():
            try:
                for table, chains in params['rules'][inet_family].items():
                    for chain, chain_rules in chains.items():
                        zone_chain = '%s_%s' % (zone, chain)
                        for rule in chain_rules:
                            yield (table, '-A %s %s' % (zone_chain, rule))
            except KeyError:
                continue

    def get_default_rules(self, inet_family):
        try:
            rules = self.config['defaults']['rules'][inet_family]
        except KeyError:
            rules = {}
        return self.get_rules(rules)

    def get_helper_chains(self, inet_family):
        try:
            rules = self.config['helper_chains'][inet_family]
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

    def get_zone_dispatchers(self, inet_family):
        for zone, params in self.config['zones'].items():
            try:
                for table, chains in params['rules'][inet_family].items():
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

    def print_rules(self, rules):
        for table in VALID_CHAINS:
            output = []
            for rule_table, rule in rules:
                if rule_table == table:
                    output.extend(self.expand_zones(rule))

            if output:
                print('*%s' % table)
                for line in output:
                    print(line)
                print('COMMIT')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', metavar='PATH', help='Path to config file')
    args = parser.parse_args()

    config_yaml = '/etc/fw-gen/config.yml'
    if args.config:
        config_yaml = args.config

    with open(config_yaml, 'r') as f:
        config = yaml.load(f)

    fw = FwGen(config)

    iptables = []
    ip6tables = []

    iptables.extend(fw.get_policy_rules('v4'))
    ip6tables.extend(fw.get_policy_rules('v6'))

    iptables.extend(fw.get_default_rules('v4'))
    ip6tables.extend(fw.get_default_rules('v6'))

    iptables.extend(fw.get_helper_chains('v4'))
    ip6tables.extend(fw.get_helper_chains('v6'))

    iptables.extend(fw.get_zone_dispatchers('v4'))
    ip6tables.extend(fw.get_zone_dispatchers('v6'))

    iptables.extend(fw.get_zone_rules('v4'))
    ip6tables.extend(fw.get_zone_rules('v6'))

    fw.print_rules(iptables)
    fw.print_rules(ip6tables)

if __name__ == '__main__':
    sys.exit(main())
