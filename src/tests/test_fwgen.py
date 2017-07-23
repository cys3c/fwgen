import pytest

from fwgen

class TestFwGen(object):
    def test_zone_expansion(self):
        config = {
            'zones':
                'lan': ['eth0', 'eth1']
                'dmz': ['eth2', 'eth3']
        }

        fwge
        rule = '-A FORWARD -i %{lan} -o ${dmz} -j ACCEPT'
        expanded = [
            '-A FORWARD -i eth0 -o eth2 -j ACCEPT',
            '-A FORWARD -i eth0 -o eth3 -j ACCEPT',
            '-A FORWARD -i eth1 -o eth2 -j ACCEPT',
            '-A FORWARD -i eth1 -o eth3 -j ACCEPT',
        ]

        assert 
