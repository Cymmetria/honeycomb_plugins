# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import tempfile
import os
import shutil

from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from pyftpdlib.authorizers import DummyAuthorizer

from base_service import ServerCustomService
from .alerts_description import CLIENT_CONNECTED_DESCRIPTION, \
    CLIENT_DISCONNECTED_DESCRIPTION, USER_LOGIN_DESCRIPTION, USER_FAILED_LOGIN_DESCRIPTION, \
    USER_LOGOUT_DESCRIPTION, USER_UPLOADED_FILE_DESCRIPTION, USER_DOWNLOADED_FILE_DESCRIPTION, \
    USER_DELETED_FILE_DESCRIPTION, USER_LISTED_DIR_DESCRIPTION, USER_NAVIGATED_DIR_DESCRIPTION, \
    USER_CREATED_DIR_DESCRIPTION, USER_DELETED_DIR_DESCRIPTION


FTP_ALERT_TYPE = "ftp"
EVENT_TYPE = "event_type"
DESCRIPTION = "event_description"
ORIGINATING_IP = "originating_ip"
ORIGINATING_PORT = "originating_port"
USERNAME = "username"
PASSWORD = "password"
ADDITIONAL_FIELDS = "additional_fields"
SERVER_IP = "0.0.0.0"
DEFAULT_USER = "admin"
DEFAULT_PASSWORD = "Password1!"


class AlertingHandler(FTPHandler):
    def __format_file_path(self, file_path):
        new_base_dir = file_path.replace(self.server.base_dir, "")
        if not new_base_dir:
            return os.sep
        return new_base_dir

    def __send_alert(self, description, alert_fields=None):
        params = {
            EVENT_TYPE: FTP_ALERT_TYPE,
            ORIGINATING_IP: self.remote_ip,
            ORIGINATING_PORT: self.remote_port,
            DESCRIPTION: description
        }
        if self.username:
            params[USERNAME] = self.username
        if self.password:
            params[PASSWORD] = self.password
        if alert_fields:
            params.update(alert_fields)

        self.server.alerting_function(params)

    def on_connect(self):
        self.__send_alert(CLIENT_CONNECTED_DESCRIPTION)

    def on_disconnect(self):
        self.__send_alert(CLIENT_DISCONNECTED_DESCRIPTION)

    def on_login(self, username):
        self.__send_alert(USER_LOGIN_DESCRIPTION)

    def on_login_failed(self, username, password):
        self.__send_alert(USER_FAILED_LOGIN_DESCRIPTION, {
            USERNAME: username,
            PASSWORD: password,
        })

    def on_logout(self, username):
        self.__send_alert(USER_LOGOUT_DESCRIPTION, {
            USERNAME: username,
        })

    def on_file_sent(self, file):
        self.__send_alert(USER_DOWNLOADED_FILE_DESCRIPTION, {
            ADDITIONAL_FIELDS: self.__format_file_path(file),
        })

    def on_file_received(self, file):
        self.__send_alert(USER_UPLOADED_FILE_DESCRIPTION, {
            ADDITIONAL_FIELDS: self.__format_file_path(file),
        })

    # On the next section we override actual handlers instead of callbacks for more alerts
    def ftp_LIST(self, path):
        self.__send_alert(USER_LISTED_DIR_DESCRIPTION, {
            ADDITIONAL_FIELDS: self.__format_file_path(path)
        })
        FTPHandler.ftp_LIST(self, path)
    
    def ftp_NLST(self, path):
        self.__send_alert(USER_LISTED_DIR_DESCRIPTION, {
            ADDITIONAL_FIELDS: self.__format_file_path(path)
        })
        FTPHandler.ftp_NLST(self, path)
    
    def ftp_MLST(self, path):
        self.__send_alert(USER_LISTED_DIR_DESCRIPTION, {
            ADDITIONAL_FIELDS: self.__format_file_path(path)
        })
        FTPHandler.ftp_MLST(self, path)
    
    def ftp_CWD(self, path):
        self.__send_alert(USER_NAVIGATED_DIR_DESCRIPTION, {
            ADDITIONAL_FIELDS: self.__format_file_path(path)
        })
        FTPHandler.ftp_CWD(self, path)
    
    def ftp_MKD(self, path):
        self.__send_alert(USER_CREATED_DIR_DESCRIPTION, {
            ADDITIONAL_FIELDS: self.__format_file_path(path)
        })
        FTPHandler.ftp_MKD(self, path)
    
    def ftp_RMD(self, path):
        self.__send_alert(USER_DELETED_DIR_DESCRIPTION, {
            ADDITIONAL_FIELDS: self.__format_file_path(path)
        })
        FTPHandler.ftp_RMD(self, path)
    
    def ftp_DELE(self, path):
        self.__send_alert(USER_DELETED_FILE_DESCRIPTION, {
            ADDITIONAL_FIELDS: self.__format_file_path(path)
        })
        FTPHandler.ftp_DELE(self, path)


class FTPAlertingServer(FTPServer):
    def __init__(self, *args, **kwargs):
        self.alerting_function = kwargs.pop("alerting_function")
        self.base_dir = kwargs.pop("base_dir")
        FTPServer.__init__(self, *args, **kwargs)


class FTPService(ServerCustomService):
    def __init__(self, *args, **kwargs):
        super(FTPService, self).__init__(*args, **kwargs)
        self.server = None
        self.temp_dir = None

    def prepare_temp_dir(self):
        self.temp_dir = tempfile.mkdtemp()

    def delete_temp_dir(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def on_server_start(self):
        self.prepare_temp_dir()
        authorizer = DummyAuthorizer()
        authorizer.add_user(DEFAULT_USER, DEFAULT_PASSWORD, homedir=self.temp_dir, perm='elradfmw')  # All permissions
        authorizer.add_anonymous(homedir=self.temp_dir, perm='elradfmw')

        handler = AlertingHandler
        handler.authorizer = authorizer
        self.server = FTPAlertingServer(
            (SERVER_IP, 21),
            handler,
            alerting_function=self.add_alert_to_queue,
            base_dir=self.temp_dir)
        self.signal_ready()
        self.server.serve_forever()

    def on_server_shutdown(self):
        if self.server:
            self.server.close_all()
        self.delete_temp_dir()

    def __str__(self):
        return "FTP"

service_class = FTPService

