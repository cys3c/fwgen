# Requirements
* At least Python 3.5
* PyYAML
* ipset

# Installation
## Debian Stretch
Install the requirements:

    apt-get install ipset python3-yaml

Put the files someplace logical. fwgen by default looks in `/etc/fwgen/` for
configuration files. As the configuration files contains the ruleset access should
be restricted.

    mkdir /etc/fwgen
    cp defaults.yml /etc/fwgen/
    touch /etc/fwgen/config.yml
    chown -R root. /etc/fwgen
    chmod 600 /etc/fwgen/*.yml

    cp fwgen.py /usr/local/bin/fwgen
    cp restore-fw /usr/local/bin/restore-fw
    ln -s /usr/local/bin/restore-fw /etc/network/if-pre-up.d/restore-fw

# Usage
Edit `/etc/fwgen/config.yml`. Look at the example configuration for guidance.

To generate the new ruleset:

    fwgen

To skip confirmation:

    fwgen --no-confirm

If ipsets in use causes issues with applying the new ruleset:

    fwgen --with-reset
