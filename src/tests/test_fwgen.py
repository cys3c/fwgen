import pytest

import fwgen

class TestFwGen(object):
    def test_zone_expansion(self):
        config['zones']['lan']['interfaces'] = ['eth0', 'eth1']
        config['zones']['dmz']['interfaces'] = ['eth2', 'eth3']

        rule = '-A FORWARD -i %{lan} -o ${dmz} -j ACCEPT'
        expanded = [
            '-A FORWARD -i eth0 -o eth2 -j ACCEPT',
            '-A FORWARD -i eth0 -o eth3 -j ACCEPT',
            '-A FORWARD -i eth1 -o eth2 -j ACCEPT',
            '-A FORWARD -i eth1 -o eth3 -j ACCEPT',
        ]

        result = fwgen.expand_zones(rule)
        assert [i for i in result] == expanded
