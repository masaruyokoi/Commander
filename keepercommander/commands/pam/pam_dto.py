import abc
import base64
import json

from keepercommander import crypto


class RouterRequest:

    def __init__(self, message_id, to, payload):
        self.id = message_id
        self.to = to
        self.payload = payload

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


# ACTION INPUTS


class GatewayActionDiscoverStartInputs:

    def __init__(self, configuration_uid, job_id):
        self.configurationUid = configuration_uid
        self.jobId = job_id

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class GatewayActionDiscoverStatusInputs:

    def __init__(self, configuration_uid, job_ids):
        self.configurationUid = configuration_uid
        self.jobIds = job_ids

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class GatewayActionDiscoverGetInputs:

    def __init__(self, configuration_uid, job_id):
        self.configurationUid = configuration_uid
        self.jobId = job_id

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


# ACTIONS

class GatewayAction(metaclass=abc.ABCMeta):

    def __init__(self, action, is_scheduled, gateway_destination=None, inputs=None, conversation_id=None):
        self.action = action
        self.is_scheduled = is_scheduled
        self.gateway_destination = gateway_destination
        self.inputs = inputs
        self.conversationId = conversation_id

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)

    @staticmethod
    def generate_conversation_id(is_bytes=False):
        message_id_bytes = crypto.get_random_bytes(16)
        if is_bytes:
            return message_id_bytes
        else:
            message_id = base64.b64encode(message_id_bytes).decode()
            return message_id


class GatewayActionGatewayInfo(GatewayAction):

    def __init__(self, conversation_id=None, is_scheduled=False):
        super().__init__(
            'gateway-info',
            conversation_id=conversation_id,
            is_scheduled=is_scheduled
        )

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class GatewayActionDiscoverStart(GatewayAction):

    def __init__(self, inputs: GatewayActionDiscoverStartInputs, conversation_id=None):
        super().__init__('discover-start', inputs=inputs, conversation_id=conversation_id, is_scheduled=True)

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class GatewayActionDiscoverStatus(GatewayAction):

    def __init__(self, inputs: GatewayActionDiscoverStatusInputs, conversation_id=None):
        super().__init__('discover-status', inputs=inputs, conversation_id=conversation_id, is_scheduled=True)

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class GatewayActionDiscoverGet(GatewayAction):

    def __init__(self, inputs: GatewayActionDiscoverGetInputs, conversation_id=None):
        super().__init__('discover-get', inputs=inputs, conversation_id=conversation_id, is_scheduled=True)

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class GatewayActionJobInfoInputs:

    def __init__(self, job_id):
        self.jobId = job_id

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class GatewayActionJobCancel(GatewayAction):

    def __init__(self, inputs: GatewayActionJobInfoInputs, conversation_id=None):
        super().__init__('job-cancel', inputs=inputs, conversation_id=conversation_id, is_scheduled=True)

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class GatewayActionJobInfo(GatewayAction):

    def __init__(self, inputs: GatewayActionJobInfoInputs, conversation_id=None):
        super().__init__('job-info', inputs=inputs, conversation_id=conversation_id, is_scheduled=False)

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class GatewayActionRotateInputs:

    def __init__(self, record_uid, configuration_uid, pwd_complexity_encrypted, resource_uid=None):
        self.recordUid = record_uid
        self.configurationUid = configuration_uid
        self.pwdComplexity = pwd_complexity_encrypted
        self.resourceRef = resource_uid

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class GatewayActionRotate(GatewayAction):

    def __init__(self, inputs: GatewayActionRotateInputs, conversation_id=None, gateway_destination=None):
        super().__init__('rotate', inputs=inputs, conversation_id=conversation_id, gateway_destination=gateway_destination,
                         is_scheduled=True)

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class GatewayActionGetConfigsInputs:

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class GatewayActionGetConfigs(GatewayAction):

    def __init__(self, conversation_id=None):
        super().__init__('get-configs', conversation_id=conversation_id, is_scheduled=False)

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class GatewayActionListAccessRecords(GatewayAction):

    def __init__(self, conversation_id=None):
        super().__init__('list-access-records', conversation_id=conversation_id, is_scheduled=False)

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)
