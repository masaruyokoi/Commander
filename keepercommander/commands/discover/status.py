import logging
import argparse
import time
import datetime
import sys
import json
from . import PAMGatewayActionDiscoverCommandBase
from ..pam.pam_dto import GatewayActionDiscoverStatusInputs, GatewayActionDiscoverStatus, GatewayAction
from ... import utils, vault_extensions
from ...proto import pam_pb2
from ..pam.router_helper import router_send_action_to_gateway
from ..pam import gateway_helper
from ...display import bcolors


class PAMGatewayActionDiscoverStatusCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='dr-discover-status-command')
    parser.add_argument('--gateway', '-g', required=False, dest='gateway', action='store',
                        help='Gateway name of UID.')
    parser.add_argument('--resource', '-rs', required=False, dest='resource_uid', action='store',
                        help='UID of the resource record. Set to discover specific resource.')
    parser.add_argument('--json', required=False, dest='json_file', action='store',
                        help='Save status to JSON file.')

    def get_parser(self):
        return PAMGatewayActionDiscoverStatusCommand.parser

    def execute(self, params, **kwargs):

        gateway_filter = kwargs.get("gateway")
        resource_uid_filter = kwargs.get("resource_uid")

        # Get all the PAM configuration records
        configuration_records = list(vault_extensions.find_records(params, "pam.*Configuration"))
        all_gateways = gateway_helper.get_all_gateways(params)

        all_jobs = []
        max_gateway_name = 12

        # For each configuration/gateway we are going to get all jobs. We are going to query the gateway for any
        # updated status.
        for configuration_record in configuration_records:

            # Load the configuration record and get the gateway_uid from the facade.
            configuration_uid = configuration_record.record_uid
            configuration_record, configuration_facade = self.get_configuration(params, configuration_uid)
            gateway_uid = configuration_facade.controller_uid

            if gateway_uid is None:
                logging.info(f"configuration {configuration_record.title} does not have a gateway set, skipping.")
                continue

            gateway = next((x for x in all_gateways if utils.base64_url_encode(x.controllerUid) == gateway_uid), None)
            if gateway is None:
                logging.debug(f"cannot find gateway for configuration {configuration_record.title}, skipping.")
                continue

            # If we are using a gateway filter, and this gateway is not the one, then go onto the next conf/gateway.
            if gateway_filter is not None and (gateway_uid != gateway_filter or
                                               gateway.controllerName.lower() != gateway_filter.lower()):
                continue

            print(f"Checking gateway {gateway.controllerName} ...", file=sys.stderr)
            if len(gateway.controllerName) > max_gateway_name:
                max_gateway_name = len(gateway.controllerName)

            # Load the discovery store
            discovery_store = self.get_discovery_store(configuration_record)

            # If the resource uid has been set, only show jobs for that resource.
            if resource_uid_filter is not None and next(
                    (x["resourceUid"] for x in discovery_store.get("jobs")
                        if x["resourceUid"] == resource_uid_filter), None) is None:
                continue

            job_lookup = {x["jobId"]: x for x in discovery_store.get("jobs")}

            action_inputs = GatewayActionDiscoverStatusInputs(
                configuration_uid=configuration_uid,
                job_ids=list(job_lookup.keys())
            )

            conversation_id = GatewayAction.generate_conversation_id()
            router_response = router_send_action_to_gateway(
                params=params,
                gateway_action=GatewayActionDiscoverStatus(
                    inputs=action_inputs,
                    conversation_id=conversation_id),
                message_type=pam_pb2.CMT_GENERAL,
                is_streaming=False,
                destination_gateway_uid_str=gateway_uid
            )
            if router_response is None:
                continue

            data = self.get_response_data(router_response)
            if data is None:
                print(f"{bcolors.FAIL}The router require returned a failure{bcolors.ENDC}")
                return

            for remote_job in data.get("jobStatus"):
                remote_job_id = remote_job.get("jobId")
                if remote_job_id in job_lookup:
                    job = job_lookup[remote_job_id]
                    job["status"] = remote_job.get("status")
                    job["addedTsStr"] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(job["addedTs"]))

                    if remote_job.get("startTs") is not None:
                        job["startTsStr"] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(remote_job["startTs"]))
                    if remote_job.get("completeTs") is not None:
                        job["completeTsStr"] = time.strftime('%Y-%m-%d %H:%M:%S',
                                                             time.localtime(remote_job["completeTs"]))
                        job["duration"] = str(datetime.timedelta(
                            seconds=int(remote_job["completeTs"]) - int(remote_job["startTs"])))
                else:
                    job_lookup[remote_job_id] = {"jobId": remote_job_id, "status": remote_job.get("status")}

                job_lookup[remote_job_id]["gateway"] = gateway.controllerName
                job_lookup[remote_job_id]["gatewayUid"] = gateway_uid

            all_jobs += [job_lookup[job_id] for job_id in job_lookup]

        # Instead if printing a table, save a json file.
        if kwargs.get("json_file") is not None:
            with open(kwargs.get("json_file"), "w") as fh:
                fh.write(json.dumps(all_jobs, indent=4))
                fh.close()
            return

        print(f"{'Gateway Name'.ljust(max_gateway_name, ' ')} "
              f"{'Gateway UID'.ljust(22, ' ')} "
              f"{'Job ID'.ljust(14, ' ')} "
              f"{'Status'.ljust(12, ' ')} "
              f"{'Resource UID'.ljust(22, ' ')} "
              f"{'Added'.ljust(19, ' ')} "
              f"{'Started'.ljust(19, ' ')} "
              f"{'Completed'.ljust(19, ' ')} "
              f"{'Duration'.ljust(19, ' ')} ")

        print(f"{''.ljust(max_gateway_name, '=')} "
              f"{''.ljust(22, '=')} "
              f"{''.ljust(14, '=')} "
              f"{''.ljust(12, '=')} "
              f"{''.ljust(22, '=')} "
              f"{''.ljust(19, '=')} "
              f"{''.ljust(19, '=')} "
              f"{''.ljust(19, '=')} "
              f"{''.ljust(19, '=')}")

        for job in all_jobs:
            color = ""
            if job['status'] == "COMPLETE":
                color = bcolors.OKGREEN
            elif job['status'] == "IN PROGRESS":
                color = bcolors.OKBLUE
            elif job['status'] == "NOT FOUND":
                color = bcolors.FAIL
            print(f"{color}{job['gateway'].ljust(max_gateway_name, ' ')} "
                  f"{job['gatewayUid']} "
                  f"{job['jobId']} "
                  f"{job['status'].ljust(12, ' ')} "
                  f"{(job.get('resourceUid') or 'NA').ljust(22, ' ')} "
                  f"{(job.get('addedTsStr') or 'NA').ljust(19, ' ')} "
                  f"{(job.get('startTsStr') or 'NA').ljust(19, ' ')} "
                  f"{(job.get('completeTsStr') or 'NA').ljust(19, ' ')} "
                  f"{(job.get('duration') or 'NA').ljust(19, ' ')} "
                  f"{bcolors.ENDC}")
