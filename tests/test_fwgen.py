import pytest

from fwgen import FwGen

class TestFwGen(object):
    def test_zone_expansion(self):
        config = {
            'zones': {
                'lan': {
                    'interfaces': ['eth0', 'eth1']
                },
                'dmz': {
                    'interfaces': ['eth2', 'eth3']
                }
            }
        }

        fw = FwGen(config)
        rule = '-A FORWARD -i %{lan} -o %{dmz} -j ACCEPT'
        rules_expanded = [
            '-A FORWARD -i eth0 -o eth2 -j ACCEPT',
            '-A FORWARD -i eth0 -o eth3 -j ACCEPT',
            '-A FORWARD -i eth1 -o eth2 -j ACCEPT',
            '-A FORWARD -i eth1 -o eth3 -j ACCEPT',
        ]

        result = [i for i in fw.expand_zones(rule)]
        assert result == rules_expanded

    def test_zone_expansion_no_zone(self):
        config = {
            'zones': {
                'lan': {
                    'interfaces': ['eth0', 'eth1']
                },
                'dmz': {
                    'interfaces': ['eth2', 'eth3']
                }
            }
        }

        fw = FwGen(config)
        rule = '-A INPUT -i lo -j ACCEPT'
        rules_expanded = [rule]

        result = [i for i in fw.expand_zones(rule)]
        assert result == rules_expanded
