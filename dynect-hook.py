#!/usr/bin/env python
# dynect hook for letsencrypt.sh
# Based on https://github.com/kappataumu/letsencrypt-cloudflare-hook and
# https://github.com/alisade/letsencrypt-DNSMadeEasy-hook.
# https://dyn.readthedocs.org/en/latest/intro.html

import os
import sys
import time
import logging
import dns.resolver

from getpass import getpass
from dyn.tm.services.dsf import DynectSession
from dyn.tm.errors import *
from dyn.tm.zones import Zone
from dyn.tm.zones import Node
from dyn.tm.records import ARecord

from tld import get_tld

logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.INFO)


def _has_dns_propagated(name, token):
    txt_records = []
    try:
        dns_resolver = dns.resolver.Resolver()
        dns_resolver.nameservers = ['8.8.8.8']
        dns_response = dns_resolver.query(name, 'TXT')
        for rdata in dns_response:
            for txt_record in rdata.strings:
                txt_records.append(txt_record)
    except dns.exception.DNSException as error:
        return False

    for txt_record in txt_records:
        if txt_record == token:
            return True

    return False

# https://dyn.readthedocs.org/en/latest/tm/zones.html
def create_txt_record(args):
    domain, token = args[0], args[2]
    zone_name = get_tld('http://' + domain)
    zone_parts = len(zone_name.split('.'))
    node_name = '.'.join(['_acme-challenge'] + domain.split('.')[:-zone_parts])
    fqdn = "{0}.{1}".format(node_name, zone_name)

    zone = Zone(zone_name)
    zone.add_record(node_name, record_type='TXT', txtdata=token, ttl=5) 
    node = zone.get_node(node_name)
    zone.publish()
    logger.info(" + TXT record created: {0}".format(fqdn))

    # give it 10 seconds to settle down and avoid nxdomain caching
    logger.info(" + Settling down for 10s...")
    time.sleep(10)

    retries=5
    while(_has_dns_propagated(fqdn, token) == False and retries > 0):
        logger.info(" + DNS not propagated, waiting 30s...")
        retries-=1
        time.sleep(30)

    if retries <= 0:
        logger.error("Error resolving TXT record for domain {0}".format(fqdn))
        sys.exit(1)


# https://dyn.readthedocs.org/en/latest/tm/zones.html
def delete_txt_record(args):
    domain, token = args[0], args[2]
    if not domain:
        logger.info(" + http_request() error in letsencrypt.sh?")
        return

    zone_name = get_tld('http://' + domain)
    zone_parts = len(zone_name.split('.'))
    node_name = '.'.join(['_acme-challenge'] + domain.split('.')[:-zone_parts])
    fqdn = "{0}.{1}".format(node_name, zone_name)

    zone = Zone(zone_name)
    node = Node(zone_name, fqdn)
    all_txt_records = node.get_all_records_by_type('TXT')
    for txt_record in all_txt_records:
        if txt_record.txtdata == (token):
            logger.info(" + Deleting TXT record name: {0}".format(fqdn))
            txt_record.delete()
    zone.publish()


def deploy_cert(args):
    domain, privkey_pem, cert_pem, fullchain_pem, chain_pem = args
    logger.info(' + ssl_certificate: {0}'.format(fullchain_pem))
    logger.info(' + ssl_certificate_key: {0}'.format(privkey_pem))
    return


def main(argv):
    try:
        dyn_cust = os.environ['DYN_CUST']
        dyn_user = os.environ['DYN_USER']
        dyn_pass = os.environ['DYN_PASS']
    except KeyError:
        dyn_cust = raw_input('Dynect customer: ')
        dyn_user = raw_input('Dynect username: ')
        dyn_pass = getpass('Dynect password: ')

    try:
        DynectSession(dyn_cust, dyn_user, dyn_pass)
    except DynectAuthError as e:
        print(e)
        sys.exit(1)

    ops = {
        'deploy_challenge': create_txt_record,
        'clean_challenge' : delete_txt_record,
        'deploy_cert'     : deploy_cert,
    }
    logger.info(" + dynect hook executing: {0}".format(argv[0]))
    ops[argv[0]](argv[1:])


if __name__ == '__main__':
    main(sys.argv[1:])
