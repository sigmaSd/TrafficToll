import argparse
import atexit
import collections
import sys
import time

from loguru import logger
from ruamel.yaml import YAML

from traffictoll.net import ProcessFilterPredicate, filter_net_connections
from traffictoll.tc import clean_up_tc, tc_add_htb_class, tc_add_u32_filter, tc_remove_u32_filter, tc_setup

CONFIG_ENCODING = 'UTF-8'
argument_parser = argparse.ArgumentParser()
argument_parser.add_argument('--logging-level', '-l', choices=logger._levels, default='INFO')
sub_parsers = argument_parser.add_subparsers(dest='action')
sub_parsers.required = True

config_parser = sub_parsers.add_parser('config')
config_parser.add_argument('--delay', '-d', type=float, default=1)
config_parser.add_argument('device')
config_parser.add_argument('config')
gui_parser = sub_parsers.add_parser('gui')


def main():
    arguments = argument_parser.parse_args()
    try:
        arguments.function(arguments)
    except KeyboardInterrupt:
        logger.info('Aborted')


def gui_main(arguments):
    from traffictoll.gui.application import start
    start()


gui_parser.set_defaults(function=gui_main)


def config_main(arguments):
    logger.stop(0)
    logger.add(sys.stderr, level=arguments.logging_level)
    with open(arguments.config, 'r', encoding=CONFIG_ENCODING) as file:
        config = YAML().load(file)

    # TODO: Parse download rate
    global_download_rate = config.get('download')
    global_upload_rate = config.get('upload')
    if global_download_rate:
        logger.info('Setting up global download limiter with max rate {}', global_download_rate)
    if global_upload_rate:
        logger.info('Setting up global upload limiter with max rate {}', global_upload_rate)

    ingress, egress = tc_setup(arguments.device, global_download_rate, global_upload_rate)
    ingress_interface, ingress_qdisc_id, ingress_root_class_id = ingress
    egress_interface, egress_qdisc_id, egress_root_class_id = egress

    atexit.register(clean_up_tc, ingress_interface, egress_interface)

    process_filter_predicates = []
    class_ids = {'ingress': {}, 'egress': {}}
    for name, process in (config.get('processes', {}) or {}).items():
        # Prepare process filter predicates to match network connections
        conditions = [list(match.items())[0] for match in process.get('match', [])]
        if not conditions:
            logger.warning('No conditions for {!r} specified, it will never be matched', name)

        predicate = ProcessFilterPredicate(name, conditions)
        process_filter_predicates.append(predicate)

        # Set up classes for download/upload limiting
        download_rate = process.get('download')
        upload_rate = process.get('upload')
        if download_rate:
            logger.info('Setting up download limiter for {!r} with max rate {}', name, download_rate)
            egress_class_id = tc_add_htb_class(ingress_interface, ingress_qdisc_id, ingress_root_class_id,
                                               download_rate)
            class_ids['ingress'][name] = egress_class_id
        if upload_rate:
            logger.info('Setting up upload limiter for {!r} with max rate {}', name, upload_rate)
            ingress_class_id = tc_add_htb_class(egress_interface, egress_qdisc_id, egress_root_class_id, upload_rate)
            class_ids['egress'][name] = ingress_class_id

    port_to_filter_id = {'ingress': {}, 'egress': {}}

    def add_ingress_filter(port, class_id):
        filter_id = tc_add_u32_filter(ingress_interface, f'match ip dport {port} 0xffff', ingress_qdisc_id, class_id)
        port_to_filter_id['ingress'][port] = filter_id

    def add_egress_filter(port, class_id):
        filter_id = tc_add_u32_filter(egress_interface, f'match ip sport {port} 0xffff', egress_qdisc_id, class_id)
        port_to_filter_id['egress'][port] = filter_id

    def remove_filters(port):
        ingress_filter_id = port_to_filter_id['ingress'].get(port)
        if ingress_filter_id:
            tc_remove_u32_filter(ingress_interface, ingress_filter_id, ingress_qdisc_id)
            del port_to_filter_id['ingress'][port]

        egress_filter_id = port_to_filter_id['egress'].get(port)
        if egress_filter_id:
            tc_remove_u32_filter(egress_interface, egress_filter_id, egress_qdisc_id)
            del port_to_filter_id['egress'][port]

    filtered_ports = collections.defaultdict(set)
    while True:
        filtered_connections = filter_net_connections(process_filter_predicates)
        for name, connections in filtered_connections.items():
            ports = set(connection.laddr.port for connection in connections)
            ingress_class_id = class_ids['ingress'].get(name)
            egress_class_id = class_ids['egress'].get(name)

            # Add new port filters
            new_ports = sorted(ports.difference(filtered_ports[name]))
            if new_ports:
                logger.info('Filtering traffic for {!r} on local ports {}', name, ', '.join(map(str, new_ports)))
                for port in new_ports:
                    if ingress_class_id:
                        add_ingress_filter(port, ingress_class_id)
                    if egress_class_id:
                        add_egress_filter(port, egress_class_id)

            # Remove old port filters
            freed_ports = sorted(filtered_ports[name].difference(ports))
            if freed_ports:
                logger.info('Removing filters for {!r} on local ports {}', name, ', '.join(map(str, freed_ports)))
                for port in freed_ports:
                    remove_filters(port)

            filtered_ports[name] = ports

        # Remove freed ports for unmatched processes (process died or predicate conditions stopped matching)
        for name in set(filtered_ports).difference(filtered_connections):
            freed_ports = sorted(filtered_ports[name])
            if freed_ports:
                logger.info('Removing filters for {!r} on local ports {}', name, ', '.join(map(str, freed_ports)))
                for port in freed_ports:
                    remove_filters(port)
            del filtered_ports[name]

        time.sleep(arguments.delay)


config_parser.set_defaults(function=config_main)
