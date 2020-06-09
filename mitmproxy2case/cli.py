import click
import os

from mitmproxy2case.flow2har import flow_parser, get_filter_rule
from mitmproxy2case.har2case import HarParser



@click.command()
@click.option('--record',default='./recording',help="mimtproxy record file")
@click.option('--filter',default='./filter.yaml',help="You can use the default: filter.yaml")
def cli(record,filter):
    entries = flow_parser(record, get_filter_rule(filter))
    HarParser(entries).gen_testcase()

