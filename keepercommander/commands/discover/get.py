import argparse
from . import PAMGatewayActionDiscoverCommandBase
from ..pam.pam_dto import GatewayActionDiscoverGetInputs, GatewayActionDiscoverGet, GatewayAction
from ... import utils, vault_extensions
from ...proto import pam_pb2
from ..pam.router_helper import router_send_action_to_gateway, router_get_connected_gateways
from ..pam import gateway_helper
from ...display import bcolors


class PAMGatewayActionDiscoverGetCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='dr-discover-command-process')
    parser.add_argument('--job-id', '-j', required=True, dest='job_id', action='store',
                        help='Discovery job id.')

    def get_parser(self):
        return PAMGatewayActionDiscoverGetCommand.parser

    def execute(self, params, **kwargs):

        if not hasattr(params, 'pam_controllers'):
            router_get_connected_gateways(params)

        job_id = kwargs.get("job_id")

        # Get all the PAM configuration records
        configuration_records = list(vault_extensions.find_records(params, "pam.*Configuration"))
        all_gateways = gateway_helper.get_all_gateways(params)

        # For each configuration/gateway we are going to get all jobs. We are going to query the gateway for any
        # updated status.
        job = None
        configuration_uid = None
        gateway_uid = None
        for configuration_record in configuration_records:

            configuration_uid = configuration_record.record_uid
            configuration_record, configuration_facade = self.get_configuration(params, configuration_uid)

            # Load the discovery store
            discovery_store, discovery_field, discovery_field_exists = self.get_discovery_store(configuration_record)

            job = next((x for x in discovery_store.get("jobs") if x["jobId"] == job_id), None)
            if job is not None:
                gateway_uid = configuration_facade.controller_uid
                gateway = next((x for x in all_gateways if utils.base64_url_encode(x.controllerUid) == gateway_uid),
                               None)
                if gateway is None:
                    print(f'{bcolors.FAIL}Discovery job gateway [{gateway_uid}] was not found.{bcolors.ENDC}')
                    return
                break

        if job is None:
            print(f'{bcolors.FAIL}Discovery job [{job_id}] was not found.{bcolors.ENDC}')
            return

        action_inputs = GatewayActionDiscoverGetInputs(
            configuration_uid=configuration_uid,
            job_id=job.get("jobId")
        )

        conversation_id = GatewayAction.generate_conversation_id()
        router_response = router_send_action_to_gateway(
            params=params,
            gateway_action=GatewayActionDiscoverGet(
                inputs=action_inputs,
                conversation_id=conversation_id),
            message_type=pam_pb2.CMT_GENERAL,
            is_streaming=False,
            destination_gateway_uid_str=gateway_uid
        )

        data = self.get_response_data(router_response)
        if data is None:
            print(f"{bcolors.FAIL}The router require returned a failure{bcolors.ENDC}")
            return

        result = self.decrypt_results(data.get("result"), key=job.get("token"))



