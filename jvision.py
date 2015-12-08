#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
A python script that uses junos-eznc and consequently ncclient and
NETCONF to massively retrieve operational data from a number of Juniper 
equipment. The data is extracted using a YAML file that defines the required
table views.
Results are tracked in log file.

Data supported in this version:
- inventory
- switching table
- vlan
- interfaces information

Example Usage:
jvision.py --hosts hosts_file.txt --log=DEBUG --inventory

'''
# Authors: {ymitsos,mmamalis}_at_noc_dot_grnet_dot_gr

import sys
import os
import re
import argparse
import getpass
import logging
import subprocess
import jnpr.junos.exception
from jexceptions import jException
from jnpr.junos import Device
from pprint import pprint as pp
from decimal import *
import multiprocessing as mp
# import yaml
# from jnpr.junos.factory.factory_loader import FactoryLoader
from jnpr.junos.factory import loadyaml
from termcolor import colored
from IPy import IP

SUCCESSFUL = 0
CONNECTION_FAILED = 1

TABLE_DEFS = loadyaml('jvision.yml')
globals().update(TABLE_DEFS)


class myDev():

    def __init__(self, hostname=None, port=None, username=None, password=None):
        self.hostname = hostname
        self.port = port
        self.username = username
        self.password = password
        self.jnprdev = Device(host=hostname,
                              username=username,
                              password=password,
                              port=port,
                              timeout=5,
                              device_params={'name': 'junos'},
                              hostkey_verify=False)
        self.rpc = self.jnprdev.rpc

    def open(self):
        try:
            self.jnprdev.open()
        except (jnpr.junos.exception.ConnectAuthError,
                jnpr.junos.exception.ConnectUnknownHostError,
                jnpr.junos.exception.ConnectRefusedError,
                jnpr.junos.exception.ProbeError,
                jnpr.junos.exception.ConnectTimeoutError) as err:
            raise jException(err)

    def facts(self):
        try:
            inventory = self.jnprdev.facts
            return inventory
        except (jnpr.junos.exception.ProbeError) as err:
            raise jException(err)

    def close(self):
        if hasattr(self.jnprdev, 'cu'):
            self.jnprdev.cu.unlock()
        self.jnprdev.close()


def macs_vision(host, logger, **kwargs):
    dv = myDev(hostname=host['address'],
               username=kwargs['username'],
               password=kwargs['password'],
               port=kwargs['port'])

    logger.info('Connecting to %s' % host['address'])

    try:
        dv.open()
    except jException as err:
        logging.info(err)
        print colored(err, 'red')
        host['status'] = CONNECTION_FAILED
        return

    facts = dv.facts()

    if facts['personality'] is not 'SWITCH':
        print colored ("""
\n%s is not a switch device... moving on""" % host['address'], 'green')
        logging.info("%s is not a switch device... moving on" % host)
        return
    else:
        macs = EtherSwTable(dv)
        macs.get()
    if not str(host['status']):
        host['status'] = SUCCESSFUL

    macs_banner = """
================================================================================
                >>> Ethernet Switching Table for %s <<<
================================================================================
""" % host['address']
    macs_header = """
VLAN               MAC address        Type      Age    Interfaces"""

    print colored("\n%s\n" % macs_banner, 'cyan'), colored("%s\n" % macs_header,
                                                           'yellow')
    with open('%s.switchtable.txt' % host['address'], 'w+') as f:
        f.write("%s%s\n" % (macs_banner, macs_header))
        for mac in macs:
            pad_vlan = ' ' * (19 - len(mac.vlan_name))
            pad_mac = ' ' * (19 - len(mac.mac))
            pad_type = ' ' * (11 - len(mac.mac_type))
            pad_age = ' ' * (6 - len(mac.mac_age))
            print("%.19s%s%s%s%s%s%s%s%s" % (mac.vlan_name, pad_vlan, mac.mac,
                                             pad_mac, mac.mac_type, pad_type,
                                             mac.mac_age, pad_age, mac.interface))

            f.write("%.19s%s%s%s%s%s%s%s%s\n" % (mac.vlan_name, pad_vlan, mac.mac,
                                                 pad_mac, mac.mac_type, pad_type,
                                                 mac.mac_age, pad_age, mac.interface))

    findmac = kwargs['findmac']
    if findmac is not 'None':
        macregex = re.compile(findmac, re.IGNORECASE)
        with open('%s.switchtable.txt' % host['address']) as f:
            for line in f.readlines():
                match = re.findall(macregex, line)
                if match:
                    print colored("""
MAC address %s was found on host: %s with details:\n %s
""" % (findmac, host['address'], line), 'yellow')

    dv.close()
    logger.info('Finished.')


def ifces_vision(host, logger, **kwargs):
    dv = myDev(hostname=host['address'],
               username=kwargs['username'],
               password=kwargs['password'],
               port=kwargs['port'])

    logger.info('Connecting to %s' % host['address'])

    try:
        dv.open()
    except jException as err:
        logging.info(err)
        print colored(err, 'red')
        host['status'] = CONNECTION_FAILED
        return

    ifces = EthPortTable(dv)
    ifces.get()
    if not str(host['status']):
        host['status'] = SUCCESSFUL

    ifces_banner = """
================================================================================
                >>> Interface information for %s <<<
================================================================================
""" % host['address']
    ifces_header = """
Interface    Admin Link  Description        MTU   Mac-Address"""
    maxlength = 0
    for port in ifces.keys():
        length = len(port)
        if length > maxlength:
            maxlength = length

    print colored("\n%s\n" % ifces_banner, 'cyan'), colored("%s\n" % ifces_header,
                                                           'yellow')
    with open('interfaces.information.txt', 'a+') as f:
        f.write("%s%s\n" % (ifces_banner, ifces_header))
        for port in ifces:
            pad_if = ' ' * (maxlength - len(port.name) + 4)
            if port.description == None:
                pad_descr = ' ' * 14
            else:
                pad_descr = ' ' * (18 - len(port.description))
            if port.admin == None:
                pad_admin = ' ' * 6
            else:
                pad_admin = ' ' * (6 - len(port.admin))
            if port.oper == None:
                pad_oper = ' ' * 6
            else:
                pad_oper = ' ' * (6 - len(port.oper))
            # pad_mtu = ' ' * (6 - len(port.mtu))
            print "%s%s%s%s%s%s%.18s %s%s  %s" % (port.name, pad_if, port.admin,
                                                  pad_admin, port.oper, pad_oper,
                                                  port.description, pad_descr,
                                                  port.mtu, port.macaddr)
            f.write("%s%s%s%s%s%s%.18s %s%s  %s\n" % (port.name, pad_if, port.admin,
                                                      pad_admin, port.oper, pad_oper,
                                                      port.description, pad_descr,
                                                      port.mtu, port.macaddr))

    dv.close()
    logger.info('Finished.')


def vlans_vision(host, logger, **kwargs):

    dv = myDev(hostname=host['address'],
               username=kwargs['username'],
               password=kwargs['password'],
               port=kwargs['port'])

    logger.info('Connecting to %s' % host['address'])

    try:
        dv.open()
    except jException as err:
        logging.info(err)
        print colored(err, 'red')
        host['status'] = CONNECTION_FAILED
        return

    facts = dv.facts()

    if facts['personality'] is not 'SWITCH':
        print colored ("""
\n%s is not a switch device... moving on""" % host['address'], 'green')
        logging.info("%s is not a switch device... moving on" % host)
        return
    else:
        if Decimal(facts['version'][0:4]) > 13.2:
            vlans = VlanElsTable(dv)
            vlans.get()
        else:
            vlans = VlanTable(dv)
            vlans.get()
        if not str(host['status']):
            host['status'] = SUCCESSFUL

        vlan_banner = """
================================================================================
                        >>> Vlan database for %s <<<
================================================================================
""" % host['address']
        print colored("\n%s" % vlan_banner, 'cyan')

        for key, value in vlans.items():
            print colored("Vlan Name: %s" % key, 'red')
            pp(value)

        with open('%s.vlan.database.txt' % host['address'], 'w+') as f:
            f.write("%s" % vlan_banner)
            for key, value in vlans.items():
                f.write("\nVlan Name: %s\n" % str(key))
                pp(value, f)

        dv.close()
        logger.info('Finished.')


def inventory_vision(host, logger, **kwargs):

    dv = myDev(hostname=host['address'],
               username=kwargs['username'],
               password=kwargs['password'],
               port=kwargs['port'])

    logger.info('Connecting to %s' % host['address'])

    try:
        dv.open()
    except jException as err:
        logging.info(err)
        print colored(err, 'red')
        host['status'] = CONNECTION_FAILED
        return

    if not str(host['status']):
        host['status'] = SUCCESSFUL

    chassis = ChassisTable(dv)
    chassis.get()
    mics = ChassisMicTable(dv)
    mics.get()
    pics = ChassisPicTable(dv)
    pics.get()
    xcvrs = XcvrTable(dv)
    xcvrs.get()

    inventory_banner = """
================================================================================
                    >>> Inventory for %s <<<
================================================================================
""" % host['address']
    inventory_header = """
Item             Version  Part number  Serial number     Description"""

    print colored("\n%s" % inventory_banner, 'cyan')
    print colored("%s" % inventory_header, 'yellow')
    with open('devices.inventory.txt', 'a+') as f:
        f.write("%s%s\n" % (inventory_banner, inventory_header))
        for item in chassis:
            pad_item = ' ' * (17 - len(item.name))
            if item.version == None:
                pad_version = ' ' * 5
            else:
                pad_version = ' ' * (9 - len(item.version))
            if item.part_number == None:
                pad_partnumber = ' ' * 9
            else:
                pad_partnumber = ' ' * (13 - len(str(item.part_number)))
            if item.serial_number == None:
                pad_serialnumber = ' ' * 14
            else:
                pad_serialnumber = ' ' * (18 - len(str(item.serial_number)))

            print "%s%s%s%s%s%s%s%s%s" % (item.name, pad_item, item.version,
                                          pad_version, item.part_number,
                                          pad_partnumber, item.serial_number,
                                          pad_serialnumber, item.description)

            f.write("%s%s%s%s%s%s%s%s%s\n" % (item.name, pad_item, item.version,
                                              pad_version, item.part_number,
                                              pad_partnumber, item.serial_number,
                                              pad_serialnumber, item.description))
    dv.close()
    logger.info('Finished.')


def pinger(jobq, resultsq, failedq):
    """
    send one ICMP request to each host
    in subnet and record output to Queue
    """
    for ip in iter(jobq.get, None):
        try:
            pinging = subprocess.call(['ping', '-n', '-c1', '-W1', ip],
                                      stdout=open('/dev/null', 'w'),
                                      stderr=subprocess.STDOUT)
            if pinging == 0:
                resultsq.put(ip)
            else:
                failedq.put(ip)
        except:
            pass


def sort_ip_list(failed):
    """
    sort ip addresses that failed to respond to icmp request
    """
    iplist = [(IP(ip).int(), ip) for ip in failed]
    iplist.sort()
    return [ip[1] for ip in iplist]


def main():

    parser = argparse.ArgumentParser(description="""Python script to display show commands to Juniper devices""",
                                     epilog="""EXAMPLE: jvision.py -t 62.217.100.1 --{action}""",
                                     add_help=False, formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('--help', dest='printhelp', action='store_true',
                        help='Print help.')
    try:
        # parse (only) --help here, before the 'required' params to other flags
        # cause problems
        printhelp = parser.parse_known_args()[0].printhelp
    except AttributeError:
        printhelp = False

    parser.add_argument('-u', '--username', dest='username', action='store',
                        default=os.environ['USER'],
                        help='username to connect to netconf server.')
    parser.add_argument('-p', '--password', dest='password', action='store',
                        help='user\'s password.')
    parser.add_argument('-t', '--target', dest='target', action='store',
                        help="""Network device to connect to. Could be a single IP e.g.
        127.0.0.1 or a network e.g. 10.0.1.0/24""""")
    parser.add_argument('--hosts', dest='hostsfile', action='store',
                        help='File with hostnames to apply configuration.')
    parser.add_argument('--port', dest='port', action='store',
                        help='NETCONF server port.')
    parser.add_argument('--logfile', dest='logfile', action='store',
                        help='File to dump logging output.')
    parser.add_argument('--log', dest='loglevel', action='store',
                        help='Loglevel. Possible values: INFO, DEBUG')
    parser.add_argument('--vlans', dest='vlans', action='store_true',
                        help='Output vlan database.')
    parser.add_argument('--ifces', dest='ifces', action='store_true',
                        help='Output Ethernet ports information.')
    parser.add_argument('--inventory', dest='inventory', action='store_true',
                        help='Device Inventory.')
    parser.add_argument('--macs', dest='macs', action='store_true',
                        help='Device Inventory.')
    parser.add_argument('--findmac', dest='findmac', action='store',
                        help='Device Inventory.')
    parser.add_argument('--fast', dest='fast', action='store_true',
                        help='Device Inventory.')

    if printhelp:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    if not (args.vlans or args.ifces or args.inventory or args.macs):
        sys.stdout.write(
            """
You have to define an action:
    --vlans flag or
    --ifces flag or
    --inventory or
    --macs (with optional --findmac flag) or
    --help for help\n
""")
        sys.exit(1)

    if not (args.target or args.hostsfile):
        sys.stdout.write(
            """
You have to define targets with either:
    -t flag or
    --hosts flag or
    --help for help\n
""")
        sys.exit(1)

    if not bool(args.target) != bool(args.hostsfile):
        sys.stdout.write(
            'Either -t or --hosts flag must be defined. Not both.\n')
        sys.exit(1)

    if not args.port:
        port = 22
    else:
        port = args.port

    if not args.password:
        args.password = getpass.getpass(args.username + '\'s Password:')

    loglevel = args.loglevel or 'info'
    numeric_level = getattr(logging, loglevel.upper(), None)

    if not numeric_level:
        sys.stderr.write('Wrong log level, using INFO instead')
        numeric_level = 20

    logfile = args.logfile or 'jvision.log'
    logging.basicConfig(filename=logfile, filemode='a', format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                        level=numeric_level, datefmt='%Y %B %d %H:%M:%S')
    logger = logging.getLogger('jvision')
    logger.info('Logging level set to %d.' % numeric_level)

    logger.info('Parsing hosts list.')
    hosts = []
    failedhosts = []

    if args.hostsfile:
        with open(args.hostsfile, mode='r') as hostsfile:
            for line in hostsfile:
                trim = line.strip()
                hosts.append({'address': trim.rstrip('\n'), 'status': ''})
    else:
        subnet = IP(args.target)
        try:
            if len(subnet) == 1:
                print'Sending icmp request to host %s' % subnet
                ping_result = subprocess.call('ping -c 1 -n -W 1 %s' % subnet,
                                              shell=True,
                                              stdout=open('/dev/null', 'w'),
                                              stderr=subprocess.STDOUT)
                if ping_result == 0:
                    hosts.append({'address': str(subnet), 'status': ''})
                    print colored("Host %s is responding to icmp request" % subnet, 'green')
                    logging.debug('Adding IP: %s to hosts list' % subnet)
                else:
                    print colored("Host %s is not responding to icmp request" % subnet, 'red')
                    logging.info(
                        "Host %s is not responding to icmp request" % subnet)
                    sys.exit(1)
            else:
                print'Starting ping sweep on subnet %s' % subnet
                jobs = mp.Queue()
                results = mp.Queue()
                failed = mp.Queue()
                pool_size = len(subnet)
                procs_pool = [mp.Process(target=pinger,
                                         args=(jobs, results, failed))
                              for i in range(pool_size)]

                for i in subnet:
                    ip = str(i)
                    jobs.put(ip)
                for p in procs_pool:
                    p.start()
                for p in procs_pool:
                    jobs.put(None)
                for p in procs_pool:
                    p.join()

                while not results.empty():
                    i = results.get()
                    hosts.append({'address': str(i), 'status': ''})
                    logging.debug('Adding IP: %s to hosts list' % i)
                while not failed.empty():
                    i = failed.get()
                    failedhosts.append(i)
                    logging.debug('Adding IP: %s to failedhosts list' % i)

                failed_sorted = sort_ip_list(failedhosts)

                with open('no_icmp_response.txt', 'w+') as f:
                    for ipaddr in failed_sorted:
                        f.write("%s\n" % ipaddr)

                print colored('Found %d hosts alive in subnet %s',
                              'green') % (len(hosts), subnet)
                print colored("""
No icmp reply from %d hosts in subnet %s (please see no_icmp_response.txt file)""",
                              'yellow') % (len(failedhosts), subnet)
        except ValueError as err:
            logging.info(err)
            print colored(err, 'red')
            sys.exit(1)

    logger.info('%d hosts found' % len(hosts))

    params = {
        'username': args.username,
        'password': args.password,
        'port': port
    }

    if args.vlans:
        for host in hosts:
            vlans_vision(host, logger, **params)

    if args.ifces:
        if 'interfaces.information.txt' in os.listdir(os.getcwd()):
            os.remove('interfaces.information.txt')
        for host in hosts:
            ifces_vision(host, logger, **params)

    if args.inventory:
        if 'devices.inventory.txt' in os.listdir(os.getcwd()):
            os.remove('devices.inventory.txt')
        for host in hosts:
            inventory_vision(host, logger, **params)

    if args.macs:
        if not args.findmac:
            params['findmac'] = 'None'
        else:
            params['findmac'] = args.findmac
        for host in hosts:
            macs_vision(host, logger, **params)

    successful_hosts = []
    connectionfailed_hosts = []

    for host in hosts:
        for key, value in host.items():
            if key == 'status' and value == SUCCESSFUL:
                successful_hosts.append(host)
            if key == 'status' and value == CONNECTION_FAILED:
                connectionfailed_hosts.append(host)

    print colored("""
-------------------------------------------------------------------------------\n""",
                  'magenta')
    print colored("Results:", "cyan")
    if len(successful_hosts) > 0:
        print colored("Executed succesfully to %d devices",
                      "green") % len(successful_hosts)
    if len(connectionfailed_hosts) > 0:
        print colored("Connection to %d devices failed",
                      "red") % len(connectionfailed_hosts)
    print colored("""
-------------------------------------------------------------------------------\n""",
                  'magenta')

    # dump results to file
    regex = re.compile('[\w.-]+grnet[\w.-]+')
    with open('failedhosts.txt', 'w+') as f:
        for i in range(len(connectionfailed_hosts)):
            match = regex.search(connectionfailed_hosts[i]['address'])
            if match:
                f.write("%s\n" % match.group())

    sys.exit(0)

if __name__ == '__main__':
    main()
