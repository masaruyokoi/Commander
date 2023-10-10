import argparse
import base64
import time
import os
from cryptography.fernet import Fernet
from . import PAMGatewayActionDiscoverCommandBase
from ..pam.router_helper import router_send_action_to_gateway, print_router_response,\
    router_get_connected_gateways
from ..pam.pam_dto import GatewayActionDiscoverStartInputs, GatewayActionDiscoverStart, GatewayAction
from ...proto import pam_pb2
from ...display import bcolors


class PAMGatewayActionDiscoverStartCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='dr-discover-start-command')
    parser.add_argument('--gateway', '-g', required=False, dest='gateway', action='store',
                        help='Gateway name of UID.')
    parser.add_argument('--resource', '-rs', required=False, dest='resource_uid', action='store',
                        help='UID of the resource record. Set to discover specific resource.')

    # TODO: remove this
    parser.add_argument('--reset-all', action='store_true', dest='reset_all',
                        help='Clear existing jobs and ignore list.')

    def get_parser(self):
        return PAMGatewayActionDiscoverStartCommand.parser

    def execute(self, params, **kwargs):

        if not hasattr(params, 'pam_controllers'):
            router_get_connected_gateways(params)

        # Load the configuration record and get the gateway_uid from the facade.
        gateway = kwargs.get('gateway')
        gateway_info = self.get_configuration_with_gateway(params, gateway)
        if gateway_info is None:
            print(f"{bcolors.FAIL}Could not find the gateway configuration for {gateway}.")

        # Get the data store from the value
        discovery_store = self.get_discovery_store(gateway_info.configuration, force_init=kwargs.get('reset_all'))

        # TODO: Check if discovery is already being done on params passed in

        # optional resource uid. if this is set, we will do discovery on this resource only.
        resource_uid = kwargs.get('resource_uid')

        # This just needs to be unique per gateway, so we don't need to make long job ids
        job_id = "DIS" + base64.urlsafe_b64encode(os.urandom(8)).decode().rstrip('=')
        token = Fernet.generate_key().decode()

        discovery_store["jobs"].append({
            "jobId": job_id,
            "token": token,
            "resourceUid": resource_uid,
            "addedTs": time.time(),
            "startedTs": None,
            "completedTs": None,
            "status": "QUEUED"
        })

        self.update_discovery_store(params, gateway_info.configuration, discovery_store)

        action_inputs = GatewayActionDiscoverStartInputs(
            configuration_uid=gateway_info.configuration_uid,
            job_id=job_id
        )

        conversation_id = GatewayAction.generate_conversation_id()
        router_response = router_send_action_to_gateway(
            params=params,
            gateway_action=GatewayActionDiscoverStart(
                inputs=action_inputs,
                conversation_id=conversation_id),
            message_type=pam_pb2.CMT_GENERAL,
            is_streaming=False,
            destination_gateway_uid_str=gateway_info.gateway_uid
        )

        print_router_response(router_response, conversation_id)
