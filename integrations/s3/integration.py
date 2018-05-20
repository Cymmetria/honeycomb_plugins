# -*- coding: utf-8 -*-
"""Honeycomb S3 Integration."""
from __future__ import unicode_literals

import os
import json
import StringIO

from boto3.session import Session

from integrationmanager import exceptions
from integrationmanager.error_messages import TEST_CONNECTION_REQUIRED
from integrationmanager.integration_utils import BaseIntegration


class S3Integration(BaseIntegration):
    """Honeycomb S3 Integration class."""

    def test_connection(self, data):
        """Test integration by validating credentials."""
        access_key = data.get('access_key')
        secret_key = data.get('secret_key')
        region = data.get('region')
        bucket = data.get('bucket')

        errors = {}

        if not access_key:
            errors['access_key'] = [TEST_CONNECTION_REQUIRED]
        if not secret_key:
            errors['secret_key'] = [TEST_CONNECTION_REQUIRED]
        if not region:
            errors['region'] = [TEST_CONNECTION_REQUIRED]
        if not bucket:
            errors['bucket'] = [TEST_CONNECTION_REQUIRED]

        if len(errors) > 0:
            return False, errors

        s3 = Session(aws_access_key_id=access_key,
                     aws_secret_access_key=secret_key,
                     region_name=region).client('s3')
        try:
            s3.list_objects_v2(Bucket=bucket, MaxKeys=1)
            success = True
            response = {}
        except Exception as exc:
            success = False
            response = {'non_field_errors': [str(exc)]}

        return success, response

    def send_event(self, alert_dict):
        """Upload alert to S3."""
        region = self.integration_data.get('region')
        bucket = self.integration_data.get('bucket')
        access_key = self.integration_data.get('access_key')
        secret_key = self.integration_data.get('secret_key')
        base_path = self.integration_data.get('base_path')

        s3 = Session(aws_access_key_id=access_key,
                     aws_secret_access_key=secret_key,
                     region_name=region).client('s3')

        image_file = alert_dict.pop("image_file")
        timestamp = alert_dict.pop("timestamp")

        alert_dict['timestamp'] = str(timestamp)
        alert_details = StringIO.StringIO(json.dumps(alert_dict))

        if not image_file:
            raise exceptions.IntegrationMissingRequiredFieldError("Missing image_file field")

        image_file_name = image_file.name.split("/")[-1]

        try:
            upload_path = os.path.join(base_path, timestamp.strftime("%Y-%m-%d"), image_file_name).lstrip('/')
            s3.upload_fileobj(image_file, bucket, upload_path)
            s3.upload_fileobj(alert_details, bucket, "{}.json".format(upload_path))
            return {}, None
        except Exception as exc:
            raise exceptions.IntegrationSendEventError(exc)

    def format_output_data(self, output_data):
        """No special formatting needed."""
        return output_data


IntegrationActionsClass = S3Integration
