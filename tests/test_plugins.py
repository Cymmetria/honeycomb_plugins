# -*- coding: utf-8 -*-
"""Honeycomb plugin tests."""

from __future__ import absolute_import

import os
import json
import signal
import subprocess

import six
import pytest
from click.testing import CliRunner
from honeycomb import defs
from honeycomb.cli import cli
from honeycomb.utils.wait import wait_until, search_json_log

from utils.defs import commands, args
from utils.test_utils import sanity_check

TEST_ARGS = "test.args.json"
RUN_HONEYCOMB = "coverage run --parallel-mode --module --source=services,integrations honeycomb".split(" ")

services = next(os.walk('services'))[1]
integrations = next(os.walk('integrations'))[1]


@pytest.fixture
def running_daemon(tmpdir, service):
    """Provide a running daemon with :func:`service_installed`."""
    # home = service_installed(service=service)
    home = str(tmpdir)
    service = os.path.join(defs.SERVICES, service)

    service_args = []
    test_args_path = os.path.join(service, TEST_ARGS)
    if os.path.exists(test_args_path):
        with open(test_args_path) as test_args_fh:
            test_args = json.loads(test_args_fh.read())
        for (k, v) in six.iteritems(test_args):
            service_args.append("{}={}".format(k, v))

    cmdargs = args.COMMON_ARGS + [home, defs.SERVICE, commands.RUN, args.EDITABLE, service] + service_args
    cmd = RUN_HONEYCOMB + cmdargs
    p = subprocess.Popen(cmd, env=os.environ)

    assert wait_until(search_json_log, filepath=os.path.join(home, defs.DEBUG_LOG_FILE), total_timeout=3,
                      key="message", value="service is ready")

    yield home, service

    p.send_signal(signal.SIGINT)
    p.wait()


# @pytest.fixture
# @pytest.mark.parametrize('service_installed', integrations)
# def integration_installed(service_installed, integration, args):
#     """Prepare honeycomb home path with DEMO_INTEGRATION installed."""
#     home = service_installed
#
#     result = CliRunner().invoke(cli, args=args.COMMON_ARGS + [home, defs.INTEGRATION,
#                                 commands.INSTALL, integration])
#     sanity_check(result, home)
#     result = CliRunner().invoke(cli, args=args.COMMON_ARGS + [home, defs.INTEGRATION,
#                                 commands.CONFIGURE, integration] + args)
#     sanity_check(result, home)
#
#     installed_integration_path = os.path.join(home, defs.INTEGRATIONS, integration)
#     assert os.path.exists(os.path.join(installed_integration_path, integrationmanager.defs.ACTIONS_FILE_NAME))
#     assert os.path.exists(os.path.join(installed_integration_path, defs.ARGS_JSON))
#
#     yield home
#
#     result = CliRunner().invoke(cli, args=args.COMMON_ARGS + [home, defs.INTEGRATION,
#                                 commands.UNINSTALL, args.YES, integration])
#     sanity_check(result, home)
#     assert os.path.exists(os.path.join(home, defs.INTEGRATIONS))
#     assert not os.path.exists(os.path.join(home, defs.INTEGRATIONS, integration))
#

@pytest.mark.parametrize('service', services)
def test_service(running_daemon, service):
    """Test all existing services."""
    home, service = running_daemon
    result = CliRunner().invoke(cli, args=args.COMMON_ARGS + [home, defs.SERVICE, commands.TEST,
                                                              args.EDITABLE, args.FORCE, service])
    sanity_check(result, home)


# @pytest.mark.parametrize('integration', integrations)
# def test_integration(integration_installed, integration):
#     """Test all integrations with simple_http service."""
#     assert integration_installed
