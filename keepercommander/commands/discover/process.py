import logging
import argparse
from . import PAMGatewayActionDiscoverCommandBase, GatewayInfo
from ..pam.pam_dto import GatewayActionDiscoverGetInputs, GatewayActionDiscoverGet, GatewayAction
from ... import utils, vault_extensions
from ...proto import pam_pb2
from ..pam.router_helper import router_send_action_to_gateway, router_get_connected_gateways
from ..pam import gateway_helper
from ...display import bcolors
from ..ksm import KSMCommand


class PAMGatewayActionDiscoverProcessCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='dr-discover-command-process')
    parser.add_argument('--job-id', '-j', required=True, dest='job_id', action='store',
                        help='Discovery job id.')
    parser.add_argument('--shared-folder-uid', '-sf', required=False, dest='shared_folder_uid',
                        action='store', help='Shared folder to place records.')
    parser.add_argument('--non-interactive', dest='as_non_interactive', action='store_true',
                        help='Non-interactive. Will add all if object id not set, or using filters.')

    def get_parser(self):
        return PAMGatewayActionDiscoverProcessCommand.parser

    def _process(self, obj, ident, params, gateway_info):

        if obj.get("ignore_object", False) is True:
            return True

        pad = ""
        if ident > 0:
            pad = "".ljust(2 * ident, ' ')

        print(f"{pad}{bcolors.OKGREEN}{obj.get('description')}{bcolors.ENDC}")
        if obj.get("record_exists", False) is False:

            do_continue = True
            while do_continue:
                print(f"{pad}Record Title: {obj.get('title')}")

                editable = []
                for field in obj.get("fields"):
                    label = field.get('label')
                    has_editable = False
                    if label in ["login", "password", "distinguishedName", "alternativeIPs", "database"]:
                        editable.append(label)
                        has_editable = True

                    field_type = field.get('type')
                    value = field.get('value')
                    if len(value) > 0:
                        value = value[0]
                    else:
                        if has_editable is True:
                            value = f"{bcolors.FAIL}MISSING{bcolors.ENDC}"
                        else:
                            value = f"{bcolors.OKBLUE}None{bcolors.ENDC}"

                    color = ""
                    if has_editable is True:
                        color = bcolors.OKGREEN
                    print(f"{pad}  "
                          f"{color}Label:{bcolors.ENDC} {label}, "
                          f"Type: {field_type}, "
                          f"Value: {value}")

                print("")
                for note in obj.get("notes", []):
                    print(f"{pad}* {note}")

                while True:
                    command = input(f"{pad}(E)dit, (A)dd, (S)kip, (I)gnore, (Q)uit> ").lower()
                    if command == "a":
                        self.create_record(
                            params,
                            record_type=obj.get("record_type"),
                            title=obj.get("title"),
                            fields=obj.get("fields"),
                            gateway_info=gateway_info
                        )


                        print(f"{pad}{bcolors.OKGREEN}Adding record{bcolors.ENDC}")
                    elif command == "e":
                        edit_label = input(f"{pad}Enter 'title' or the name of the label to edit, "
                                           "RETURN to cancel> ")
                        if edit_label == "":
                            break
                        if edit_label.lower() == "title":
                            new_title = input(f"{pad}Enter new title> ")
                            obj["title"] = new_title
                        elif edit_label in editable:
                            new_value = input(f"Enter new value> ")
                            for edit_field in obj.get("fields"):
                                if edit_field['label'] == edit_label:
                                    edit_field['value'] = [new_value]
                        else:
                            print(
                                f"{pad}{bcolors.FAIL}The field is not editable.{bcolors.ENDC}")
                            continue
                    elif command == "i":
                        pass
                    elif command == "s":
                        print(f"{pad}{bcolors.OKBLUE}Skipping record{bcolors.ENDC}")
                        do_continue = False
                        break
                    elif command == "q":
                        return False
                print()

        for next_key in ["users", "directories", "machines", "databases"]:
            for next_obj in obj.get(next_key, []):
                if self._process(next_obj, ident + 2, params, gateway_info) is False:
                    return

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
        gateway_info = None
        for configuration_record in configuration_records:

            configuration_uid = configuration_record.record_uid
            configuration_record, configuration_facade = self.get_configuration(params, configuration_uid)

            # Load the discovery store
            discovery_store = self.get_discovery_store(configuration_record)

            job = next((x for x in discovery_store.get("jobs") if x["jobId"] == job_id), None)
            if job is not None:
                gateway_uid = configuration_facade.controller_uid
                gateway = next((x for x in all_gateways if utils.base64_url_encode(x.controllerUid) == gateway_uid),
                               None)
                if gateway is None:
                    print(f'{bcolors.FAIL}Discovery job gateway [{gateway_uid}] was not found.{bcolors.ENDC}')
                    return

                application_id = utils.base64_url_encode(gateway.applicationUid)
                application = KSMCommand.get_app_record(params, application_id)
                if application is None:
                    logging.debug(f"cannot find application for gateway {gateway}, skipping.")

                gateway_info = GatewayInfo(
                    configuration=configuration_record,
                    facade=configuration_facade,
                    gateway=gateway,
                    application=application,
                )

                break

        if job is None:
            print(f'{bcolors.FAIL}Discovery job [{job_id}] was not found.{bcolors.ENDC}')
            return

        action_inputs = GatewayActionDiscoverGetInputs(
            configuration_uid=gateway_info.configuration_uid,
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
            destination_gateway_uid_str=gateway_info.gateway_uid
        )

        data = self.get_response_data(router_response)
        if data is None:
            print(f"{bcolors.FAIL}The router require returned a failure{bcolors.ENDC}")
            return

        result = self.decrypt_results(data.get("result"), key=job.get("token"))

        self._process(result, ident=0, params=params, gateway_info=gateway_info)
