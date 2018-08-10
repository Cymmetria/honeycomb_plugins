# -*- coding: utf-8 -*-
"""Honeycomb plugin tests."""

from __future__ import absolute_import

import os
import sys
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

TEST_ARGS_FILE = "test.args.json"
RUN_HONEYCOMB = "coverage run --parallel-mode --module " \
                "--source={} honeycomb".format(",".join([defs.SERVICES, defs.INTEGRATIONS])).split(" ")

services = next(os.walk(defs.SERVICES))[1]
integrations = next(os.walk(defs.INTEGRATIONS))[1]


@pytest.fixture
def running_daemon(tmpdir, request):
    """Provide a daemoninzed service."""
    def install_service():
        """Install a service (and its dependencies)."""
        result = CliRunner().invoke(cli, args=args.COMMON_ARGS + [home, defs.SERVICE,
                                    commands.INSTALL, service_path])
        sanity_check(result, home)
        assert os.path.exists(os.path.join(home, defs.SERVICES, service_name, "{}_service.py".format(service_name)))

    def uninstall_service():
        """Uninstall a service."""
        result = CliRunner().invoke(cli, args=args.COMMON_ARGS + [home, defs.SERVICE, commands.UNINSTALL,
                                                                  args.YES, service_name])
        sanity_check(result, home)
        assert os.path.exists(os.path.join(home, defs.SERVICES))
        assert not os.path.exists(os.path.join(home, defs.SERVICES, service_name))

    def get_test_args():
        """Resolve test args from file."""
        service_args = []
        test_args_path = os.path.join(service_path, TEST_ARGS_FILE)
        if os.path.exists(test_args_path):
            with open(test_args_path) as test_args_fh:
                test_args = json.loads(test_args_fh.read())
            for (k, v) in six.iteritems(test_args):
                service_args.append("{}={}".format(k, v))

        return service_args

    def start_service():
        """Launch service in daemon mode."""
        # Import the installed service venv to path for any installed dependencies
        installed_venv = os.path.realpath(os.path.join(home, defs.SERVICES, service_name, defs.DEPS_DIR))
        venv_env = os.environ.copy()
        venv_env["PYTHONPATH"] = "{}:{}".format(installed_venv, ":".join(sys.path))
        sys.path.insert(0, installed_venv)

        cmdargs = args.COMMON_ARGS + [home, defs.SERVICE, commands.RUN, args.EDITABLE, service_path] + service_args
        p = subprocess.Popen(RUN_HONEYCOMB + cmdargs, env=venv_env)

        assert wait_until(search_json_log, filepath=os.path.join(home, defs.DEBUG_LOG_FILE), total_timeout=300,
                          key="message", value="service is ready")
        return p

    def stop_service():
        p.send_signal(signal.SIGINT)
        p.wait()
        assert wait_until(search_json_log, filepath=os.path.join(home, defs.DEBUG_LOG_FILE), total_timeout=3,
                          key="message", value="Caught KeyboardInterrupt, shutting service down gracefully")

    home = str(tmpdir)
    service_name = request.param
    service_path = os.path.join(defs.SERVICES, service_name)

    install_service()
    service_args = get_test_args()
    p = start_service()

    yield home, service_path

    stop_service()
    uninstall_service()


# @pytest.fixture
# @pytest.mark.parametrize("service_installed", integrations)
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

@pytest.mark.parametrize("running_daemon", services, indirect=True)
def test_service(running_daemon):
    """Test all existing services."""
    home, service = running_daemon
    result = CliRunner().invoke(cli, args=args.COMMON_ARGS + [home, defs.SERVICE, commands.TEST,
                                                              args.EDITABLE, args.FORCE, service])
    sanity_check(result, home)


# @pytest.mark.parametrize("integration", integrations)
# def test_integration(integration_installed, integration):
#     """Test all integrations with simple_http service."""
#     assert integration_installed
