import logging
import os
from ..base import Command
from ..pam.config_facades import PamConfigurationRecordFacade
from ...vault import TypedField, TypedRecord
from ... import vault, record_management
from ...display import bcolors
from ..pam.router_helper import get_response_payload, router_set_record_rotation_information
from ..pam.gateway_helper import get_all_gateways
from ... import utils, vault_extensions
from ..ksm import KSMCommand
from cryptography.fernet import Fernet
import json
from ...proto import router_pb2
from ... import loginv3
from ... import api, subfolder, crypto


class GatewayInfo:
    def __init__(self, configuration, facade, gateway, application):
        self.configuration = configuration
        self.facade = facade
        self.gateway = gateway
        self.application = application
        self._shared_folder_uid = None

    @property
    def gateway_uid(self):
        return utils.base64_url_encode(self.gateway.controllerUid)

    @property
    def configuration_uid(self):
        return self.configuration.record_uid

    @property
    def shared_folder_uid(self):
        return self.facade.folder_uid


class PAMGatewayActionDiscoverCommandBase(Command):

    """
    The discover command base.

    Contains static methods to get the configuration record, get and update the discovery store. These are method
    used by multiple discover actions.
    """

    # If the discovery data field does not exist, or the field contains no values, use the template to init the
    # field.

    STORE_LABEL = "discoveryStore"

    @staticmethod
    def blank_job_field_value():
        return json.dumps({"ignoreList": [], "jobs": []})

    @staticmethod
    def default_job_field():
        return TypedField.new_field(field_type="text",
                                    field_label=PAMGatewayActionDiscoverCommandBase.STORE_LABEL,
                                    field_value=[PAMGatewayActionDiscoverCommandBase.blank_job_field_value()])

    @staticmethod
    def get_discovery_store_field(configuration_record):

        discovery_field = None
        if configuration_record.custom is not None:
            discovery_field = next((field
                                    for field in configuration_record.custom
                                    if field.label == PAMGatewayActionDiscoverCommandBase.STORE_LABEL), None)

        return discovery_field

    @staticmethod
    def get_configuration_with_gateway(params, gateway):

        """
        Find the configuration using the gateway UID or Name

        Returns a tuple of configuration record, facade, and the gatewwy UID

        """

        # Get all the PAM configuration records
        configuration_records = list(vault_extensions.find_records(params, "pam.*Configuration"))
        all_gateways = get_all_gateways(params)

        info = None
        for record in configuration_records:

            # Load the configuration record and get the gateway_uid from the facade.
            configuration_record = vault.KeeperRecord.load(params, record.record_uid)
            configuration_facade = PamConfigurationRecordFacade()
            configuration_facade.record = configuration_record

            configuration_gateway_uid = configuration_facade.controller_uid
            if configuration_gateway_uid is None:
                logging.debug(f"configuration {configuration_record.title} does not have a gateway set, skipping.")
                continue

            # Get the gateway for this configuration
            found_gateway = next((x for x in all_gateways if utils.base64_url_encode(x.controllerUid) ==
                                  configuration_gateway_uid), None)
            if found_gateway is None:
                logging.debug(f"cannot find gateway for configuration {configuration_record.title}, skipping.")
                continue

            application_id = utils.base64_url_encode(found_gateway.applicationUid)
            application = KSMCommand.get_app_record(params, application_id)
            if application is None:
                logging.debug(f"cannot find application for gateway {gateway}, skipping.")

            if (utils.base64_url_encode(found_gateway.controllerUid) == gateway or
                    found_gateway.controllerName.lower() == gateway):

                info = GatewayInfo(
                    configuration=configuration_record,
                    facade=configuration_facade,
                    gateway=found_gateway,
                    application=application
                )

        return info

    @staticmethod
    def get_configuration(params, configuration_uid):

        configuration_record = vault.KeeperRecord.load(params, configuration_uid)
        if not isinstance(configuration_record, vault.TypedRecord):
            print(f'{bcolors.FAIL}PAM Configuration [{configuration_uid}] is not available.{bcolors.ENDC}')
            return

        configuration_facade = PamConfigurationRecordFacade()
        configuration_facade.record = configuration_record

        return configuration_record, configuration_facade

    @staticmethod
    def get_discovery_store(configuration_record, force_init=False):

        """
        Get the discovery store from the vault

        The discovery store is JSON stored in a Custom Field.
        """

        if force_init is True:
            logging.debug("resetting the discovery store")
            discovery_field = PAMGatewayActionDiscoverCommandBase.default_job_field()
        else:

            # Get the discovery store. It contains information about discovery job for a configuration. It is on the
            # custom fields.

            discovery_field = PAMGatewayActionDiscoverCommandBase.get_discovery_store_field(configuration_record)
            if discovery_field is None:
                logging.debug("discovery store field does not exists, creating")
                discovery_field = PAMGatewayActionDiscoverCommandBase.default_job_field()
            else:
                logging.debug("discovery store record exists")

            # The value should not be [], if it is, init with the defaults.
            if len(discovery_field.value) == 0:
                logging.debug("discovery store does not have a value, set to the default value")
                discovery_field.value = PAMGatewayActionDiscoverCommandBase.default_job_field()

        discovery_store = json.loads(discovery_field.value[0])

        return discovery_store

    @staticmethod
    def update_discovery_store(params, configuration_record, discovery_store):

        discovery_field = PAMGatewayActionDiscoverCommandBase.get_discovery_store_field(configuration_record)
        discovery_store_value = [json.dumps(discovery_store)]

        if discovery_field is None:
            discovery_field = TypedField.new_field(field_type="text",
                                                   field_label=PAMGatewayActionDiscoverCommandBase.STORE_LABEL,
                                                   field_value=discovery_store_value)
            if configuration_record.custom is None:
                configuration_record.custom = []
            configuration_record.custom.append(discovery_field)
        else:
            discovery_field.value = discovery_store_value

        # Update the record here to prevent a race-condition
        record_management.update_record(params, configuration_record)
        params.sync_data = True

    @staticmethod
    def get_response_data(router_response):

        response = router_response.get("response")
        if response.get("status") != "OK":
            logging.warning("Router request return an failure status")
            return None

        payload = get_response_payload(router_response)
        return payload.get("data")

    @staticmethod
    def decrypt_results(result, key):
        return json.loads(Fernet(key.encode()).decrypt(result.encode()).decode())

    @staticmethod
    def map_user_map(params, gateway_uid):

        user_records = list(vault_extensions.find_records(params, "pamUser"))
        for user_record in user_records:
            pass

    def create_record(self, params, record_type, title, fields, gateway_info, parent_resource_uid=None):

        # For pamUser records, we required the record UID of the resource that will rotate this user.
        if record_type == "pamUser" and parent_resource_uid is None:
            raise ValueError("The pamUser requires a parent resource uid.")
        else:
            # If this is a resource record, then  we don't need to set the parent_resource_uid since it belongs
            # to the gateway/configuration record.
            parent_resource_uid = None

        record_key = os.urandom(32)

        folder_type = "shared_folder"
        shared_folder = params.shared_folder_cache[gateway_info.shared_folder_uid]
        if shared_folder is None:
            raise ValueError(f"The folder id was not found for shared_folder_uid {gateway_info.shared_folder_uid}")
        if isinstance(shared_folder, subfolder.SharedFolderFolderNode):
            folder_type = "shared_folder_folder"
        folder_key = crypto.encrypt_aes_v2(record_key, shared_folder['shared_folder_key_unencrypted'])

        logging.debug(f"shared folder type is {folder_type}")

        record_uid = api.generate_record_uid()
        logging.debug('Generated Record UID: %s', record_uid)
        data_dict = {
            "title": title,
            "type": record_type,
            "fields": fields,
            "custom": [],
            "notes": "Added by Discovery"
        }
        record = {
            'record_uid': record_uid,
            'record_key_unencrypted': record_key,
            'client_modified_time': api.current_milli_time(),
            'data_unencrypted': json.dumps(data_dict)
        }

        res = api.add_record_v3(params, record,
                                record_uid=record_uid,
                                rq={
                                    "folder_type": folder_type,
                                    "folder_uid": gateway_info.shared_folder_uid,
                                    "folder_key": folder_key
                                })
        if res is not None:
            params.sync_data = True

            url_safe_str_to_bytes = loginv3.CommonHelperMethods.url_safe_str_to_bytes

            rq = router_pb2.RouterRecordRotationRequest()
            rq.recordUid = url_safe_str_to_bytes(record_uid )
            rq.revision = 0
            rq.configurationUid = url_safe_str_to_bytes(gateway_info.configuration_uid)
            if parent_resource_uid is not None:
                rq.resourceUid = url_safe_str_to_bytes(parent_resource_uid)
            rq.schedule = ""
            rs = router_set_record_rotation_information(params, rq)

        params.sync_data = True
