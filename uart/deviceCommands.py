
from math import fabs
from cryptography.hazmat.primitives.serialization import \
    Encoding, PrivateFormat, PublicFormat, NoEncryption, \
    load_der_private_key, load_der_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
import time
import json
import logging
import logging.config
logging.config.fileConfig(fname='../config/log.conf',
                          disable_existing_loggers=False)
log = logging.getLogger("deviceCommands.py")

# logging.basicConfig(filename='app.log', filemode='w',
#                     format='%(asctime)s - %(levelname)s - %(name)s - %(lineno)d - %(message)s', level=logging.DEBUG)
# DeviceCommands
DeviceCommands = {
    "meshClear": {
        "opcode": "AC",
        "length": 1,
        "length_res": 3
    },
    "setKeypair": {
        "opcode": "69",
        "length": 97,
        "length_res": 3
    },
    "setLocalUnicast": {
        "opcode": "9F",
        "length": 5,
        "length_res": 3
    },
    "getLocalUnicast": {
        "opcode": "A0",
        "length": 1,
        "length_res": 0
    },
    "setNetKey": {
        "opcode": "92",
        "length": 19,
        "length_res": 0
    },
    "setAppKey": {
        "opcode": "97",
        "length": 21,
        "length_res": 0
    },
    "add_addrSubscription": {
        "opcode": "A1",
        "length": 3,
        "length_res": 0
    },
    "remove_addrSubscription": {
        "opcode": "A3",
        "length": 3,
        "length_res": 0
    },
    "add_addrPublication": {
        "opcode": "A4",
        "length": 3,
        "length_res": 0
    },
    "remove_addrPublication": {
        "opcode": "A6",
        "length": 3,
        "length_res": 0
    },
    "send_meshPacket": {
        "opcode": "AB",
        "lengthMin": 11,
        "lengthMax": 255,
        "length_res": 0
    },
    "scanStart": {
        "opcode": "61",
        "length": 1,
        "length_res": 0
    },
    "scanStop": {
        "opcode": "62",
        "length": 1,
        "length_res": 0
    },
    "Provisioning": {
        "opcode": "63",
        "length": 45,
        "length_res": 0
    },
    "provListen": {
        "opcode": "64",
        "length": 1,
        "length_res": 0
    },
    "provisioningOOBUse": {
        "opcode": "66",
        "length": 5,
        "length_res": 0
    },
    "provECDHSecret": {
        "opcode": "68",
        "length": 34,
        "length_res": 0
    },
    "add_devkey": {
        "opcode": "9C",
        "length": 21,
        "length_res": 0
    },
    "devkey_delete": {
        "opcode": "9D",
        "length": 3,
        "length_res": 0
    },
    "getIv": {
        "opcode": "AF",
        "length": 1,
        "length_res": 0
    },
    "red_iv": {
        "opcode": "AE",
        "length": 12,
        "length_res": 0
    }



}

localUnicast = ""
NetworkKey = ""
# Messages summary
sigMessageOpcode = {
    "8204": "onOffStatus",
    "824E": "lightnessStatus",
    "8003": "appKeyStatus",
    "02": "compositionStatus",
    "803E": "modelAppStatus",
    "804A": "delete_node",
    "801F": "configSubscribeModelAddStatus"
}
sigMessageOpcodeSet = {
    "appKeyAdd": "00",
    "composition": "8008",  # 8008
    "bind_key_model": "803D",
    "delete_node": "8049",
    "config_subscribe_model_add": "801B",
    "config_subscribe_model_delete": "801C"
}

PRIVATE_BYTES_START = 36
PRIVATE_BYTES_END = PRIVATE_BYTES_START + 32


class REQUEST:

    """class interface in DeviceCommands SigMesh"""

    def __init__(self):
        __private_key = ec.generate_private_key(ec.SECP256R1(),
                                                default_backend())
        __public_key = __private_key.public_key()
        self.public_key = self.public_key_to_raw(__public_key)
        self.private_key = self.private_key_to_raw(__private_key)

    def ECDH_shared_secret(self, peerPublic, nodePrivate):
        byte_public_key = bytes.fromhex(peerPublic)
        byte_nodePrivate = bytes.fromhex(nodePrivate)
        public_key_peer = self.raw_to_public_key(byte_public_key)
        private_key = self.raw_to_private_key(byte_nodePrivate)
        self.shared_secret_b = private_key.exchange(ec.ECDH(), public_key_peer)
        shared_secret = ""
        for x in range(len(self.shared_secret_b)):
            shared_secret += (str("%0.2X" % self.shared_secret_b[x]))
        return shared_secret

    def public_key_to_raw(self, public_key):
        public_key_der = public_key.public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        # Public key is the last 64 bytes of the formatted key.
        self.public_key_der = public_key_der[len(public_key_der) - 64:]
        public_key_der_str = ""
        for x in range(len(self.public_key_der)):
            public_key_der_str += (str("%0.2X" % self.public_key_der[x]))
        return public_key_der_str

    def private_key_to_raw(self, private_key):
        private_key_pkcs8 = private_key.private_bytes(
            Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
        # Key is serialized in the PKCS8 format, but we need the raw key bytestring
        # The raw key is found from byte 36 to 68 in the formatted key.
        self.private_key_pkcs8 = private_key_pkcs8[PRIVATE_BYTES_START:PRIVATE_BYTES_END]
        private_key_pkcs8_str = ""
        for x in range(len(self.private_key_pkcs8)):
            private_key_pkcs8_str += (str("%0.2X" % self.private_key_pkcs8[x]))
        return private_key_pkcs8_str

    def raw_to_private_key(self, private_bytes):
        assert (len(private_bytes) == 32)
        # A private key in PKCS8+DER format.
        # We'll simply replace the actual key bytes.
        PKCS8_FMT = b'0\x81\x87\x02\x01\x000\x13\x06\x07*\x86H\xce=\x02\x01\x06\x08*\x86H\xce=\x03\x01\x07\x04m0k\x02\x01\x01\x04 \xd3e\xef\x9d\xbdc\x89\xe0.K\xc5\x84^P\r:\x9b\xfd\x038 _r`\x17\xac\xf2JJ\xff\x07\x9d\xa1D\x03B\x00\x044\xfa\xfa+E\xfa}Aj\x9e\x118N\x10\xc8r\x04\xa7e\x1d\xd2JdK\xfa\xcd\x02\xdb{\x90JA-\x0b)\xba\x05N\xa7E\x80D>\xa2\xbc"\xe3k\x89\xd1\x10*ci\x19-\xed|\xb7H\xea=L`'  # NOQA
        key = PKCS8_FMT[:PRIVATE_BYTES_START]
        key += private_bytes
        key += PKCS8_FMT[PRIVATE_BYTES_END:]
        private_key = load_der_private_key(
            key, password=None, backend=default_backend())
        return private_key

    def raw_to_public_key(self, public_bytes):
        # log.debug("len public key: ", len(public_bytes))
        assert (len(public_bytes) == 64)
        # A public key in the DER format.
        # We'll simply replace the actual key bytes.
        DER_FMT = b'0Y0\x13\x06\x07*\x86H\xce=\x02\x01\x06\x08*\x86H\xce=\x03\x01\x07\x03B\x00\x044\xfa\xfa+E\xfa}Aj\x9e\x118N\x10\xc8r\x04\xa7e\x1d\xd2JdK\xfa\xcd\x02\xdb{\x90JA-\x0b)\xba\x05N\xa7E\x80D>\xa2\xbc"\xe3k\x89\xd1\x10*ci\x19-\xed|\xb7H\xea=L`'  # NOQA
        key = DER_FMT[:-64]
        key += public_bytes

        public_key = load_der_public_key(key, backend=default_backend())
        return public_key

    def reverse_data(self, data):
        """đảo bit dữ liệu trước khi gửi"""
        tmp = ""
        if (len(data) == 4):
            tmp = data[2:4]+data[0:2]
        elif (len(data) == 8):  # 800A 0000
            tmp = data[2:4]+data[0:2]+data[6:8]+data[4:6]
        return tmp

    def mesh_clear(self):
        """xóa network, lệnh này không có data"""
        #log.info("mesh_clear request")
        tmp = DeviceCommands["meshClear"]["opcode"]
        lent = len(tmp)//2
        if lent == DeviceCommands["meshClear"]["length"]:
            tmp = str("%0.2X" % lent)+tmp
            return tmp
        else:
            return None

    def get_iv(self):
        """get iv, lệnh này không có data"""
        #log.info("get_iv request")
        tmp = DeviceCommands["getIv"]["opcode"]
        lent = len(tmp)//2
        if lent == DeviceCommands["getIv"]["length"]:
            tmp = str("%0.2X" % lent)+tmp
            return tmp
        else:
            return None

    def red_iv(self, indexIV, str_Seqnum, ivUpdateInProgress="00", ivUpdateTimeoutCounter="0000"):
        """set iv"""
        # log.info("red_iv request")
        tmp = DeviceCommands["red_iv"]["opcode"] + indexIV + \
            ivUpdateInProgress + ivUpdateTimeoutCounter + str_Seqnum
        lent = len(tmp)//2
        if lent == DeviceCommands["red_iv"]["length"]:
            tmp = str("%0.2X" % lent)+tmp
            return tmp
        else:
            return None

    def set_keypair(self):
        """Send a public/private keypair to the device"""
        # log.info("set_keypair request")

        # khởi tạo data
        tmp = DeviceCommands["setKeypair"]["opcode"] + \
            self.private_key + \
            self.public_key
        # tmp = "69" + "58B1DF2C64990A2ED34BDC3E49D2E602671248636D5022BA70993D620845A27D" + \
        #     "AFED4E011F3B619BE969C22A0059E062576784A86C45CD03C8D891B56117CC3E5702F1F1BDB20864F9EFA052BED72BB64A81A67172DE3CEADEB0E34DC2356930"
        lent = len(tmp)//2
        # kiểm tra đúng độ dài không
        if lent == DeviceCommands["setKeypair"]["length"]:
            tmp = str("%0.2X" % lent)+tmp
            return tmp
        else:
            return None

    def set_local_unicast(self, startAddress, count=1):
        """Set the start and count of the device's local unicast address
            Start Address(2byte): First address in the range of unicast addresses
            Count(2byte): Number of addresses in the range of unicast addresses.
        """
        #log.info("set_local_unicast request")
        global localUnicast
        localUnicast = startAddress  # ghi lai địa chỉ unicast để sử dụng cho các lệnh sau
        count = self.reverse_data(
            str("%0.4X" % count))
        # khởi tạo data
        tmp = DeviceCommands["setLocalUnicast"]["opcode"] + \
            self.reverse_data(startAddress) + count
        lent = len(tmp)//2
        # kiểm tra đúng độ dài không
        if lent == DeviceCommands["setLocalUnicast"]["length"]:
            tmp = str("%0.2X" % lent)+tmp
            return tmp
        else:
            return None

    def get_local_unicast(self):
        """Get the start and count of the device's local unicast addresses."""
        #log.info("get_local_unicast request")
        tmp = DeviceCommands["getLocalUnicast"]["opcode"]
        lent = len(tmp)//2
        if lent == DeviceCommands["getLocalUnicast"]["length"]:
            tmp = str("%0.2X" % lent)+tmp
            return tmp
        else:
            return None

    def set_netkey(self, netKey, netKeyIndex=0):
        #log.info("set_netkey request")
        global NetworkKey
        NetworkKey = netKey
        netKeyIndex = self.reverse_data(str("%0.4X" % netKeyIndex))
        tmp = DeviceCommands["setNetKey"]["opcode"] + netKeyIndex + netKey
        lent = len(tmp)//2
        if lent == DeviceCommands["setNetKey"]["length"]:
            tmp = str("%0.2X" % lent)+tmp
            return tmp
        else:
            return None

    def set_appkey(self, appKey, appKeyIndex=0, subnetHandle=0):
        #log.info("set_appkey request")
        appKeyIndex = self.reverse_data(str("%0.4X" % appKeyIndex))
        subnetHandle = self.reverse_data(
            str("%0.4X" % subnetHandle))
        tmp = DeviceCommands["setAppKey"]["opcode"] + \
            appKeyIndex + subnetHandle + appKey
        lent = len(tmp)//2
        if lent == DeviceCommands["setAppKey"]["length"]:
            tmp = str("%0.2X" % lent)+tmp
            return tmp
        else:
            return None

    def add_addrSubscription(self, Address):
        """ Add the specified address to the set of active address subscriptions.
                Type        Name	    Size    Offset  Description
                uint16_t    Address	    2       0       Address to add as a subscription address.
        """
        #log.info("add_addrSubscription request")
        tmp = DeviceCommands["add_addrSubscription"]["opcode"] + \
            self.reverse_data(Address)
        lent = len(tmp)//2
        if lent == DeviceCommands["add_addrSubscription"]["length"]:
            tmp = str("%0.2X" % lent)+tmp
            return tmp
        else:
            return None

    def remove_addrSubscription(self, AddressHandle):
        """ Remove the address with the given handle from the set of active address subscriptions.
                Type        Name	            Size    Offset  Description
                uint16_t    Address Handle		2       0       Handle of address to remove from address subscription list.

        """
        #log.info("remove_addrSubscription request")
        tmp = DeviceCommands["remove_addrSubscription"]["opcode"] + \
            self.reverse_data(AddressHandle)
        lent = len(tmp)//2
        if lent == DeviceCommands["remove_addrSubscription"]["length"]:
            tmp = str("%0.2X" % lent)+tmp
            return tmp
        else:
            return None

    def add_addrPublication(self, Address):
        """ Add the specified address to the set of active publish addresses.
                Type        Name	    Size    Offset  Description
                uint16_t    Address	    2       0       Address to add as a publication address.
        """
        #log.info("add_addrPublication request")
        tmp = DeviceCommands["add_addrPublication"]["opcode"] + \
            self.reverse_data(Address)
        lent = len(tmp)//2
        if lent == DeviceCommands["add_addrPublication"]["length"]:
            tmp = str("%0.2X" % lent)+tmp
            return tmp
        else:
            return None

    def remove_addrPublication(self, AddressHandle):
        """ Remove the address with the specified handle from the set of active publish addresses.
                Type        Name	            Size    Offset  Description
                uint16_t    Address Handle		2       0       Handle of the address to remove from the publication address list.
        """
        #log.info("remove_addrPublication request")
        tmp = DeviceCommands["remove_addrPublication"]["opcode"] + \
            self.reverse_data(AddressHandle)
        lent = len(tmp)//2
        if lent == DeviceCommands["remove_addrPublication"]["length"]:
            tmp = str("%0.2X" % lent)+tmp
            return tmp
        else:
            return None

    def send_meshPacket(self, DST_Addr_Handle, Data, AppkeyHandle=0, SRC_Addr="", TTL=8, Force_Segmented=0, Transmic_Size=0, Friendship_Credential_Flag=0):
        """ Send a mesh packet. The source address handle must represent a local unicast address.
        Type	        Name	                    Size    Offset  Description
        uint16_t        Appkey Handle               2       0       Appkey or devkey handle to use for packet sending. Subnetwork will be picked automatically.
        uint16_t        SRC Addr                    2       2       Raw unicast address to use as source address. Must be in the range of local unicast addresses.
        uint16_t        DST Addr Handle             2       4       Handle of destination address to use in packet.
        uint8_t         TTL                         1       6       Time To Live value to use in packet.
        uint8_t         Force Segmented             1       7       Whether or not to force use of segmented message type for the transmission.
        uint8_t         Transmic Size               1       8       Transport MIC size used enum. SMALL=0, LARGE=1, DEFAULT=2. LARGE may only be used with segmented packets.
        uint8_t         Friendship Credential Flag  1       9       Control parameter for credentials used to publish messages from a model. 0 for master, 1 for friendship.
        uint8_t[244]    Data                        0..244  10      Payload of the packet.
        ***
            DST_Addr_Handle (kiểu MSB byte cao trước )
            SRC_Addr là localUnicast trong lúc set_localUnicast (kiểu MSB)
            data = opcode + mesage
        ***
        """
        #log.info("send_meshPacket to %s", DST_Addr_Handle)
        if SRC_Addr == "":
            SRC_Addr = localUnicast

        if AppkeyHandle == 0:
            AppkeyHandle = self.reverse_data(str("%0.4X" % AppkeyHandle))
        else:
            AppkeyHandle = self.reverse_data(AppkeyHandle)  # devKeyHandle
        tmp = DeviceCommands["send_meshPacket"]["opcode"] +\
            AppkeyHandle +\
            self.reverse_data(SRC_Addr) +\
            self.reverse_data(DST_Addr_Handle) +\
            (str("%0.2X" % TTL)) +\
            (str("%0.2X" % Force_Segmented)) +\
            (str("%0.2X" % Transmic_Size)) +\
            (str("%0.2X" % Friendship_Credential_Flag)) +\
            Data
    # 1F  AB 0100 0100 0000 08000000 00 000000 BF56D55C019D257FC28B6D67F1E40ED2
        # AB 0000 0100 0000 08000000 8202 0104
        # AB 0000 0100 0001 08000000 8202 0003
        lent = len(tmp)//2
        if lent >= DeviceCommands["send_meshPacket"]["lengthMin"] & lent <= DeviceCommands["send_meshPacket"]["lengthMax"]:
            tmp = str("%0.2X" % lent)+tmp
            return tmp
        else:
            return None

    def scanStart(self):
        """Start reporting of incoming unprovisioned beacons."""
        #log.info("scanStart request")
        tmp = DeviceCommands["scanStart"]["opcode"]
        lent = len(tmp)//2
        if lent == DeviceCommands["scanStart"]["length"]:
            tmp = str("%0.2X" % lent)+tmp
            return tmp
        else:
            return None

    def scanStop(self):
        """Stop reporting of incoming unprovisioned beacons."""
        #log.info("scanStop request")
        tmp = DeviceCommands["scanStop"]["opcode"]
        lent = len(tmp)//2
        if lent == DeviceCommands["scanStop"]["length"]:
            tmp = str("%0.2X" % lent)+tmp
            return tmp
        else:
            return None

    def Provisioning(self, ContextID, UUID, netkeyIndex, address, IvIndex=0, IvUpdateFlag=0, KeyRefreshFlag=0, AttentionDurationS=0):
        """Start provisioning of a device. 
        When a provisioning link has been successfully established, a Provisioning Link Established event is received. 
        If an error occurs, a Provisioning Link Closed event is received. 
        After a link has been established, a Provisioning Capabilities Received event will be emitted upon receiving the peer node's OOB capabilities. 
        To continue the provisioning process, a Provisioning OOB Use command must be sent to select which kind of OOB authentication to use.
        """
        #log.info("Provisioning request")
        tmp = DeviceCommands["Provisioning"]["opcode"] +\
            (str("%0.2X" % ContextID)) +\
            UUID+NetworkKey +\
            (str("%0.4X" % netkeyIndex)) +\
            self.reverse_data(str("%0.8X" % IvIndex)) +\
            self.reverse_data(address) +\
            (str("%0.2X" % IvUpdateFlag)) +\
            (str("%0.2X" % KeyRefreshFlag)) +\
            (str("%0.2X" % AttentionDurationS))
        lent = len(tmp)//2
        if lent == DeviceCommands["Provisioning"]["length"]:
            tmp = str("%0.2X" % lent)+tmp
            return tmp
        else:
            return None

    def prov_listen(self):
        """As an uprovisioned device, listen for incoming provisioning requests."""
        #log.info("Provisioning Listen request")
        tmp = DeviceCommands["provListen"]["opcode"]
        lent = len(tmp)//2
        if lent == DeviceCommands["provListen"]["length"]:
            tmp = str("%0.2X" % lent)+tmp
            return tmp
        else:
            return None

    def provisioningOOBUse(self, ContextID, oOBMethod=0, oOBAction=0, size=0):
        #log.info("provisioningOOBUse request")
        tmp = DeviceCommands["provisioningOOBUse"]["opcode"] +\
            (str("%0.2X" % ContextID)) +\
            (str("%0.2X" % oOBMethod)) +\
            (str("%0.2X" % oOBAction)) +\
            (str("%0.2X" % size))
        lent = len(tmp)//2
        if lent == DeviceCommands["provisioningOOBUse"]["length"]:
            tmp = str("%0.2X" % lent)+tmp
            return tmp
        else:
            return None

    def provisioningECDHSecret(self, peerPublic, nodePrivate, ContextID=0):
        #log.info("provisioningECDHSecret request")

        shared_secret = self.ECDH_shared_secret(peerPublic, nodePrivate)
        tmp = DeviceCommands["provECDHSecret"]["opcode"] +\
            (str("%0.2X" % ContextID)) +\
            shared_secret
        lent = len(tmp)//2
        if lent == DeviceCommands["provECDHSecret"]["length"]:
            tmp = str("%0.2X" % lent)+tmp
            return tmp
        else:
            return None

    def add_devkey(self, unicast, addrHandle, devKey):
        #log.info("add devkey request")

        tmp = DeviceCommands["add_devkey"]["opcode"] +\
            self.reverse_data(unicast) +\
            "0000" +\
            devKey
        lent = len(tmp)//2
        if lent == DeviceCommands["add_devkey"]["length"]:
            tmp = str("%0.2X" % lent)+tmp
            return tmp
        else:
            return None

    def delete_node(self, addrHandle, devKey):
        #log.info("add devkey request")

        data = ""
        data = sigMessageOpcodeSet["delete_node"]

        return self.send_meshPacket(addrHandle, data, devKey)

    def devkey_delete(self, AddressHandle):

        #log.info("delete devkey request: %s", AddressHandle)
        tmp = DeviceCommands["devkey_delete"]["opcode"] + \
            self.reverse_data(AddressHandle)
        lent = len(tmp)//2
        if lent == DeviceCommands["devkey_delete"]["length"]:
            tmp = str("%0.2X" % lent)+tmp
            return tmp
        else:
            return None

    def appkey_bind(self, netkeyIndex, appkeyIndex, appKey, addrHandle, devHandle):

        #log.info("appKey Add request: %s", appKey)

        NetKeyIndexAndAppKeyIndex = list()
        NetKeyIndexAndAppKeyIndex.append(
            str("%0.2X" % (int(appkeyIndex, base=16) >> 4)))
        NetKeyIndexAndAppKeyIndex.append(str("%0.2X" % (
            (int(appkeyIndex, base=16) << 4) | int(netkeyIndex, base=16) >> 8)))
        NetKeyIndexAndAppKeyIndex.append(
            str("%0.2X" % (int(netkeyIndex, base=16))))
        NetKeyIndexAndAppKeyIndex = ''.join(NetKeyIndexAndAppKeyIndex)
        data = ""
        data = sigMessageOpcodeSet["appKeyAdd"] + \
            NetKeyIndexAndAppKeyIndex + appKey

        return self.send_meshPacket(addrHandle, data, devHandle)

    def composition(self, addrHandle, devHandle):

        #log.info("get composition request")

        data = ""
        data = sigMessageOpcodeSet["composition"] + "00"

        return self.send_meshPacket(addrHandle, data, devHandle)

    def bind_key_model(self, addrHandle, devHandle, elementAddress, appKeyIndex, modelIdentifier):

        #log.info("set bind_key_model request")

        data = ""
        data = sigMessageOpcodeSet["bind_key_model"]+self.reverse_data(elementAddress) + self.reverse_data(appKeyIndex) + \
            self.reverse_data(modelIdentifier)

        return self.send_meshPacket(addrHandle, data, devHandle)

    def config_subscribe_model_add(self, addrHandle, devHandle, elementAddress, subscribeAddress, modelIdentifier):

        #log.info("config_subscribe_model_add request")

        data = ""
        data = sigMessageOpcodeSet["config_subscribe_model_add"]+self.reverse_data(elementAddress) + self.reverse_data(subscribeAddress) + \
            self.reverse_data(modelIdentifier)

        return self.send_meshPacket(addrHandle, data, devHandle)

    def config_subscribe_model_delete(self, addrHandle, devHandle, elementAddress, subscribeAddress, modelIdentifier):

        #log.info("config_subscribe_model_delete request")

        data = ""
        data = sigMessageOpcodeSet["config_subscribe_model_delete"]+self.reverse_data(elementAddress) + self.reverse_data(subscribeAddress) + \
            self.reverse_data(modelIdentifier)

        return self.send_meshPacket(addrHandle, data, devHandle)


class RESPONSE:
    def __init__(self, tp="method", pl="params"):
        self.tp = tp
        self.pl = pl

    def res(self, tmp):
        if (tmp[1] == 0x84):
            for x in DeviceCommands:
                if (int(DeviceCommands[x]["opcode"], 16) == tmp[2]) & ((DeviceCommands[x]["length_res"] == tmp[0]) | (DeviceCommands[x]["length_res"] == 0)):
                    return getattr(self, x, lambda: 'not a binary digit')(tmp)
        elif (tmp[1] == 0xD0) | (tmp[1] == 0xD1):
            if tmp[0] >= 22:
                if ((tmp[21] & 0x80) == 0x00):
                    # opcode 1 byte
                    opcode = str("%0.2X" % tmp[21])
                    for x in sigMessageOpcode:
                        if (x == opcode):
                            return getattr(self, sigMessageOpcode[x], lambda: 'not a binary digit')(tmp)
                    return None
                elif ((tmp[21] & 0xC0) == 0x80):
                    # opcode 2 byte sig message
                    opcode = str("%0.2X" % tmp[21])+str("%0.2X" % tmp[22])
                    for x in sigMessageOpcode:
                        if (x == opcode):
                            return getattr(self, sigMessageOpcode[x], lambda: 'not a binary digit')(tmp)

                    return None
                elif (tmp[21] & 0xC0 == 0xC0):
                    # opcdoe 3 byte
                    return None
            return self.app_data(tmp)

        elif (tmp[1] == 0xC0):
            # #log.info("Unprovisioned Received")
            return self.UnprovisionedReceived(tmp)

        # elif (tmp[1] == 0xC1):
            #log.info("Link Established")
            # return self.LinkEstablished(tmp)

        elif (tmp[1] == 0xC2):
            #log.info("Provisioning link closed")
            return self.provClosed(tmp)
            # return self.LinkClosed(tmp)

        elif (tmp[1] == 0xC3):
            #log.info("Provisioning Received Capabilities")
            return self.ReceivedCapabilities(tmp)

        elif (tmp[1] == 0xC5):
            #log.info("Provisioning Complete")
            return self.provComplete(tmp)

        elif (tmp[1] == 0xC7):
            #log.info("ECDH reponst")
            return self.ECDH_reponst(tmp)

        elif (tmp[1] == 0xD9):
            #log.info("ECDH reponst")
            return self.iv_reponst(tmp)

        else:
            return None

    def meshClear(self, tmp):
        #log.info("meshClear received")
        msg = {self.tp: "mesh_clear", self.pl: {"status": ""}}
        msg[self.pl]["status"] = str("%0.2X" % tmp[3])
        return msg

    def getIv(self, tmp):
        log.info("getIv received")
        # msg = {self.tp: "mesh_clear", self.pl: {"status": ""}}
        # msg[self.pl]["status"] = str("%0.2X" % tmp[3])
        # return msg

    def red_iv(self, tmp):
        # log.info("red_iv received")
        msg = {self.tp: "red_iv", self.pl: {"status": ""}}
        msg[self.pl]["status"] = str("%0.2X" % tmp[3])
        return msg

    def iv_reponst(self, tmp):
        # log.info("iv_reponst received")
        msg = {self.tp: "iv_reponst", self.pl: {"indexIV": ""}}
        msg[self.pl]["indexIV"] = str(
            "%0.2X" % tmp[2]) + str("%0.2X" % tmp[3]) + str("%0.2X" % tmp[4]) + str("%0.2X" % tmp[5])
        return msg

    def setKeypair(self, tmp):
        #log.info("setKeypair received")
        msg = {self.tp: "setKeypair", self.pl: {"status": ""}}
        msg[self.pl]["status"] = str("%0.2X" % tmp[3])
        return msg

    def setLocalUnicast(self, tmp):
        """
            status:
                00: thành công
                8E: đã set rồi
        """
        #log.info("setLocalUnicast received")
        msg = {self.tp: "setLocalUnicast", self.pl: {"status": ""}}
        msg[self.pl]["status"] = str("%0.2X" % tmp[3])
        return msg

    def getLocalUnicast(self, tmp):
        """
            status:
                00: thành công
                8E: đã set rồi
        """
        #log.info("getLocalUnicast received")
        msg = {self.tp: "getLocalUnicast", self.pl: {"status": ""}}
        msg[self.pl]["status"] = str("%0.2X" % tmp[3])
        if msg[self.pl]["status"] == "00":
            msg[self.pl]["unicast"] = (
                str("%0.2X" % tmp[5])+str("%0.2X" % tmp[4]))
        # msg[self.pl]["unicast"] = self.reverse_data(
        #     str("%0.4X" % tmp[3:4]))

        return msg

    def setNetKey(self, tmp):
        #log.info("setNetKey received")
        msg = {self.tp: "setNetKey", self.pl: {"status": ""}}
        msg[self.pl]["status"] = str("%0.2X" % tmp[3])
        return msg

    def setAppKey(self, tmp):
        #log.info("setAppKey received")
        msg = {self.tp: "setAppKey", self.pl: {"status": ""}}
        msg[self.pl]["status"] = str("%0.2X" % tmp[3])
        return msg

    def add_addrSubscription(self, tmp):
        #log.info("add_addrSubscription received")
        msg = {self.tp: "addr_subscription_add", self.pl: {"status": ""}}
        msg[self.pl]["status"] = str("%0.2X" % tmp[3])
        if msg[self.pl]["status"] == "00":
            msg[self.pl]["address"] = (
                str("%0.2X" % tmp[5])+str("%0.2X" % tmp[4]))
        return msg

    def remove_addrSubscription(self, tmp):
        #log.info("remove_addrSubscription received")
        msg = {self.tp: "addr_subscription_remove", self.pl: {"status": ""}}
        msg[self.pl]["status"] = str("%0.2X" % tmp[3])
        if msg[self.pl]["status"] == "00":
            msg[self.pl]["address"] = (
                str("%0.2X" % tmp[5])+str("%0.2X" % tmp[4]))
        return msg

    def add_addrPublication(self, tmp):
        #log.info("add_addrPublication received")
        msg = {self.tp: "addr_publication_add", self.pl: {"status": ""}}
        msg[self.pl]["status"] = str("%0.2X" % tmp[3])
        if msg[self.pl]["status"] == "00":
            msg[self.pl]["address"] = (
                str("%0.2X" % tmp[5])+str("%0.2X" % tmp[4]))
        return msg

    def remove_addrPublication(self, tmp):
        #log.info("remove_addrPublication received")
        msg = {self.tp: "addr_publication_remove", self.pl: {"status": ""}}
        msg[self.pl]["status"] = str("%0.2X" % tmp[3])
        if msg[self.pl]["status"] == "00":
            msg[self.pl]["address"] = (
                str("%0.2X" % tmp[5])+str("%0.2X" % tmp[4]))
        return msg

    def send_meshPacket(self, tmp):
        #log.info("send_meshPacket received")
        msg = {self.tp: "data ack", self.pl: {"status": ""}}
        msg[self.pl]["status"] = str("%0.2X" % tmp[3])
        return msg

    def onOffStatus(self, tmp):
        #log.info("onOffStatus received")
        msg = {
            self.tp: "onOffStatus",
            self.pl: {
                "o": "8204",
                "a": "",
                "ttl": "",
                "p": ""
            }
        }
        msg[self.pl]["a"] = str("%0.2X" % tmp[3]) + str("%0.2X" % tmp[2])
        msg[self.pl]["ttl"] = str("%0.2X" % tmp[10])
        for x in range(23, tmp[0]+1):
            msg[self.pl]["p"] += str("%0.2X" % tmp[x])
        return msg

    def appKeyStatus(self, tmp):
        #log.info("appKeyStatus received")
        msg = {
            self.tp: "appkey_bind",
            self.pl: {
                "status": "",
                "unicast": ""
            }
        }
        msg[self.pl]["status"] = str("%0.2X" % tmp[23])
        return msg

    def reverse_data(self, data):
        """đảo bit dữ liệu trước khi gửi"""
        tmp = ""
        if (len(data) == 4):
            tmp = data[2:4]+data[0:2]
        elif (len(data) == 8):  # 800A 0000
            tmp = data[2:4]+data[0:2]+data[6:8]+data[4:6]
        return tmp

    def lightnessStatus(self, tmp):
        #log.info("lightnessStatus received")
        msg = {
            self.tp: "lightnessStatus",
            self.pl: {
                "o": "824E",
                "a": "",
                "ttl": "",
                "p": ""
            }
        }
        msg[self.pl]["a"] = str("%0.2X" % tmp[3]) + str("%0.2X" % tmp[2])
        msg[self.pl]["ttl"] = str("%0.2X" % tmp[10])
        msg1 = ""
        if tmp[0] == 27:
            for x in range(25, tmp[0]):
                msg1 += str("%0.2X" % tmp[x])
        elif tmp[0] == 24:
            for x in range(23, tmp[0]+1):
                msg1 += str("%0.2X" % tmp[x])

        msg[self.pl]["p"] = self.reverse_data(msg1)
        return msg

    def scanStart(self, tmp):
        #log.info("scanStart received")
        msg = {self.tp: "scanStart", self.pl: {"status": ""}}
        msg[self.pl]["status"] = str("%0.2X" % tmp[3])
        return msg

    def scanStop(self, tmp):
        #log.info("scanStop received")
        msg = {self.tp: "scanStop", self.pl: {"status": ""}}
        msg[self.pl]["status"] = str("%0.2X" % tmp[3])
        return msg

    def UnprovisionedReceived(self, tmp):
        #log.info("UnprovisionedReceived received")
        msg = {
            self.tp: "unprovisioning",
            self.pl: {
                "addr type": "",
                "gatt supported": "",
                "rssi": "",
                "mac": "",
                "uuid": ""
            }
        }
        for x in range(2, 18):
            msg[self.pl]["uuid"] += str("%0.2X" % tmp[x])
        msg[self.pl]["rssi"] = "-" + str(tmp[18])
        msg[self.pl]["gatt supported"] = str("%0.2X" % tmp[19])
        msg[self.pl]["addr type"] = str("%0.2X" % tmp[20])
        for x in range(21, 27):
            msg[self.pl]["mac"] += str("%0.2X" % tmp[x])
            if x < 26:
                msg[self.pl]["mac"] += "-"

        return msg

    def Provisioning(self, tmp):
        #log.info("provision received")
        msg = {self.tp: "provision", self.pl: {"status": ""}}
        msg[self.pl]["status"] = str("%0.2X" % tmp[3])
        if msg[self.pl]["status"] == "00":
            msg[self.pl]["context"] = str("%0.2X" % tmp[4])
        return msg

    def ReceivedCapabilities(self, tmp):
        #log.info("prov Capabilities received")
        if tmp[0] == 0x0b:
            msg = {self.tp: "prov_capabilities", self.pl: {"context": "", "numElements": "", "publicKeyType": "",
                                                           "staticOOBTypes": "", "outputOOBSize": "", "outputOOBActions": "", "inputOOBSize": "", "inputOOBActions": ""}}
            msg[self.pl]["context"] = str("%0.2X" % tmp[2])
            msg[self.pl]["numElements"] = str("%0.2X" % tmp[3])
            msg[self.pl]["publicKeyType"] = str("%0.2X" % tmp[4])
            msg[self.pl]["staticOOBTypes"] = str("%0.2X" % tmp[5])
            msg[self.pl]["outputOOBSize"] = str("%0.2X" % tmp[6])
            msg[self.pl]["outputOOBActions"] = str(
                "%0.2X" % tmp[8]) + str("%0.2X" % tmp[7])
            msg[self.pl]["inputOOBSize"] = str("%0.2X" % tmp[9])
            msg[self.pl]["inputOOBActions"] = str(
                "%0.2X" % tmp[11]) + str("%0.2X" % tmp[10])
            return msg

    def provListen(self, tmp):
        #log.info("provListen received")
        msg = {self.tp: "provListen", self.pl: {"status": ""}}
        msg[self.pl]["status"] = str("%0.2X" % tmp[3])
        return msg

    def provisioningOOBUse(self, tmp):
        #log.info("provisioning OOB Use received")
        msg = {self.tp: "provOOBUse", self.pl: {"status": ""}}
        msg[self.pl]["status"] = str("%0.2X" % tmp[3])
        if msg[self.pl]["status"] == "00":
            msg[self.pl]["context"] = str("%0.2X" % tmp[4])
        return msg

    def provECDHSecret(self, tmp):
        #log.info("provisioning ECDH Secret received")
        msg = {self.tp: "provECDHSecret", self.pl: {"status": ""}}
        msg[self.pl]["status"] = str("%0.2X" % tmp[3])
        if msg[self.pl]["status"] == "00":
            msg[self.pl]["context"] = str("%0.2X" % tmp[4])
        return msg

    def ECDH_reponst(self, tmp):
        #log.info("provisioning ECDH Secret received")
        msg = {self.tp: "ECDH_reponst", self.pl: {
            "context": "", "peerPublic": "", "nodePrivate": ""}}
        msg[self.pl]["context"] = str("%0.2X" % tmp[2])
        for x in range(3, 67):
            msg[self.pl]["peerPublic"] += str("%0.2X" % tmp[x])
        for y in range(67, 99):
            msg[self.pl]["nodePrivate"] += str("%0.2X" % tmp[y])
        return msg

    def provComplete(self, tmp):
        if tmp[0] == 0x2c:
            msg = {self.tp: "provComplete", self.pl: {
                "context": "", "ivIndex": "", "deviceKey": "", "netKey": ""}}
            msg[self.pl]["context"] = str("%0.2X" % tmp[2])
            msg[self.pl]["ivIndex"] = str(
                "%0.2X" % tmp[6])+str("%0.2X" % tmp[5])+str("%0.2X" % tmp[4])+str("%0.2X" % tmp[3])
            msg[self.pl]["netKeyIndex"] = str(
                "%0.2X" % tmp[8])+str("%0.2X" % tmp[7])
            msg[self.pl]["address"] = str(
                "%0.2X" % tmp[10])+str("%0.2X" % tmp[9])
            msg[self.pl]["ivUpdateFlag"] = str("%0.2X" % tmp[11])
            msg[self.pl]["keyRefreshFlag"] = str("%0.2X" % tmp[12])
            for x in range(13, 29):
                msg[self.pl]["deviceKey"] += str("%0.2X" % tmp[x])
            for x in range(29, 45):
                msg[self.pl]["netKey"] += str("%0.2X" % tmp[x])
            return msg

    def provClosed(self, tmp):
        #log.info("provClosed received")
        msg = {self.tp: "provClosed", self.pl: {
            "status": "00"}}
        return msg

    def add_devkey(self, tmp):
        #log.info("add devkey received")
        msg = {self.tp: "devkey_add", self.pl: {
            "status": "", "devkeyHandle": ""}}
        msg[self.pl]["status"] = str("%0.2X" % tmp[3])
        if msg[self.pl]["status"] == "00":
            msg[self.pl]["devkeyHandle"] = str(
                "%0.2X" % tmp[5]) + str("%0.2X" % tmp[4])
        return msg

    def devkey_delete(self, tmp):
        #log.info("delete devkey received")
        msg = {self.tp: "devkey_delete", self.pl: {
            "status": "", "devkeyHandle": ""}}
        msg[self.pl]["status"] = str("%0.2X" % tmp[3])
        if msg[self.pl]["status"] == "00":
            msg[self.pl]["devkeyHandle"] = str(
                "%0.2X" % tmp[5]) + str("%0.2X" % tmp[4])
        return msg

    def compositionStatus(self, tmp):
        #log.info("composition Status received")
        msg = {
            self.tp: "composition",
            self.pl: {
                "unicast": "",
                "status": "00",
                "cid": "0059",
                "pid": "0000",
                "vid": "0000",
                "crpl": "0028",
                "relay": "",
                "proxy": "",
                "friends": "",
                "low power": "",
                "elements": [{}]
            }
        }
        # opcode 1 byte data bat dau tu byte 22
        msg[self.pl]["cid"] = str("%0.2X" % tmp[24]) + str("%0.2X" % tmp[23])
        msg[self.pl]["pid"] = str("%0.2X" % tmp[26]) + str("%0.2X" % tmp[25])
        msg[self.pl]["vid"] = str("%0.2X" % tmp[28]) + str("%0.2X" % tmp[27])
        msg[self.pl]["crpl"] = str("%0.2X" % tmp[30]) + str("%0.2X" % tmp[29])
        Features = "{:08b}".format(
            int((str("%0.2X" % tmp[32]) + str("%0.2X" % tmp[31])), 16))

        relay = Features[7]
        # if relay == "0":
        #     relay = False
        # elif relay == "1":
        #     relay = True
        msg[self.pl]["relay"] = int(relay)

        proxy = Features[6]
        # if proxy == "0":
        #     proxy = False
        # elif proxy == "1":
        #     proxy = True
        msg[self.pl]["proxy"] = int(proxy)

        friends = Features[6]
        # if friends == "0":
        #     friends = False
        # elif friends == "1":
        #     friends = True
        msg[self.pl]["friends"] = int(friends)

        lowPower = Features[5]
        # if lowPower == "0":
        #     lowPower = False
        # elif lowPower == "1":
        #     lowPower = True
        msg[self.pl]["low power"] = int(lowPower)
        self.byteIndex = 32

        for i in range(4):
            msg[self.pl]["elements"][i]["location"] = str(
                "%0.2X" % tmp[self.byteIndex+2]) + str("%0.2X" % tmp[self.byteIndex+1])  # 33 34
            msg[self.pl]["elements"][i]["index"] = i
            msg[self.pl]["elements"][i]["models"] = self.element_dev(tmp)
            if self.byteIndex == tmp[0]:
                break

        return msg

    def element_dev(self, tmp):
        numS = tmp[self.byteIndex+3]  # 35
        numV = tmp[self.byteIndex+4]  # 36
        models = []
        for x in range(0, numS*2, 2):
            hb = self.byteIndex+5+x+1  # 37+x+1
            lb = self.byteIndex+5+x  # 37+x+1
            models.append(str("%0.2X" % tmp[hb]) + str("%0.2X" % tmp[lb]))
        self.byteIndex = hb
        for y in range(0, numV*2, 2):
            hb = self.byteIndex+1+y+1
            lb = self.byteIndex+1+y
            models.append(str("%0.2X" % tmp[hb]) + str("%0.2X" % tmp[lb])+str(
                "%0.2X" % tmp[hb+2]) + str("%0.2X" % tmp[lb+2]))
            hb = hb+2
        self.byteIndex = hb
        return models

    def modelAppStatus(self, tmp):
        #log.info("modelAppStatus received")
        msg = {self.tp: "bind_key_model", self.pl: {"status": "00", "element address": "0002",
                                                    "unicast": "", "apkey index": "0000", "model identifier": "1000"}}
        msg[self.pl]["status"] = str("%0.2X" % tmp[23])
        if msg[self.pl]["status"] == "00":
            msg[self.pl]["element address"] = str(
                "%0.2X" % tmp[25]) + str("%0.2X" % tmp[24])
            msg[self.pl]["apkey index"] = str(
                "%0.2X" % tmp[27]) + str("%0.2X" % tmp[26])
            if tmp[0] == 29:  # model 2 byte
                msg[self.pl]["model identifier"] = str(
                    "%0.2X" % tmp[29]) + str("%0.2X" % tmp[28])
            elif tmp[0] == 31:  # model 4 byte
                msg[self.pl]["model identifier"] = str("%0.2X" % tmp[29]) + str(
                    "%0.2X" % tmp[28]) + str("%0.2X" % tmp[31]) + str("%0.2X" % tmp[30])

        return msg

    def delete_node(self, tmp):
        # log.info("delete_node recived")
        msg = {self.tp: "delete_node", self.pl: {
            "status": "00", "unicast": ""}}
        msg[self.pl]["unicast"] = str("%0.2X" % tmp[3]) + str("%0.2X" % tmp[2])
        return msg

    def configSubscribeModelAddStatus(self, tmp):
        # log.info("delete_node recived")
        msg = {
            self.tp: "config_subscribe_model_add",
            self.pl: {
                "status": "00",
                "element address": "",
                "addr": "",
                "model identifier": ""
            }

        }
        msg[self.pl]["status"] = str("%0.2X" % tmp[23])
        if msg[self.pl]["status"] == "00":
            msg[self.pl]["element address"] = str(
                "%0.2X" % tmp[25])+str("%0.2X" % tmp[24])
            msg[self.pl]["addr"] = str(
                "%0.2X" % tmp[27])+str("%0.2X" % tmp[26])
            if tmp[0] == 29:  # model 2 byte
                msg[self.pl]["model identifier"] = str(
                    "%0.2X" % tmp[29]) + str("%0.2X" % tmp[28])
            elif tmp[0] == 31:  # model 4 byte
                msg[self.pl]["model identifier"] = str("%0.2X" % tmp[29]) + str(
                    "%0.2X" % tmp[28]) + str("%0.2X" % tmp[31]) + str("%0.2X" % tmp[30])
        return msg
