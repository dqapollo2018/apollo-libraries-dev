
import random
from re import I
import time
from distutils.log import error
from importlib.util import set_loader
from tkinter.messagebox import NO
from deviceCommands import REQUEST, RESPONSE
import json
import threading
from serial import Serial
import logging
import logging.config
logging.config.fileConfig(fname='../config/log.conf',
                          disable_existing_loggers=False)
log = logging.getLogger("uart.py")
dev_req = REQUEST()

url_config_db = "config_db.json"

url_sigMesh_db = "sigMesh_db.json"

NUMBER_REPEAT = 10  # số lần gửi lại
TIME_REPEAT = 0.2  # thời gian giữa các lần gửi s


class UART:
    def __init__(self, port, baud, tp="method", pl="params", timeout=1):
        """init uart with input: port, baud
            tp = "method" # key cho topic data response
            pl = "params" # key cho payload data response
        """
        self.repeat = None
        self.num_repeat = 0
        self.tpRepeat = None
        self.set_keypair = {}
        self.set_localUnicast = {}
        self.set_netkey = {}
        self.set_appkey = {}
        self.handle = None
        self.tp = tp
        self.pl = pl

        self.devkey_add_unicast = ""
        global dev_res
        dev_res = RESPONSE(self.tp, self.pl)
        self.status_fb = False  # dùng để feedback lỗi và những topic không cần xử lý
        self.res_error = {self.tp: "", self.pl: {"status": ""}}
        try:
            self.serial = Serial(port, baud, timeout=timeout)
            log.info("init serial successful")
        except:
            log.error("error init serial")
            exit(0)
        self.send_config()

    def scan_device(self, status):
        """
        tìm kiếm các thiết bị chưa được thêm vào mạng
            - status: 
                + True: start scan
                + False: stop scan
        ví dụ: 
            scan_device(True) --> bắt đầu scan
            scan_device(False) --> kết thúc lệnh scan để thực hiện các lệnh tiếp theo
        """
        if status:
            # start scan
            self.uartWrite(dev_req.scanStart())
        else:
            # stop scan
            self.uartWrite(dev_req.scanStop())

    def add_device(self, name, uuid):
        """
            thêm 1 thiết bị mới vào mạng
                - name: tên thiết bị kiểu String
                - uuid: uuid của thiết bị có được sau lệnh scan
            ví dụ:
                add_device("den2", "018071902600008CAEB1514719020000") 
            --> thêm thiết bị có uuid là "018071902600008CAEB1514719020000" với tên den2
        """
        self.prov_deviceName = name

        f = open(url_sigMesh_db, "r")
        data_sigMesh = json.loads(f.read())
        f.close()
        unicast = 3

        for node in data_sigMesh["nodes"]:
            if node["name"] != self.prov_deviceName:
                if int(node["unicastAddress"], base=16) >= unicast:
                    unicast = int(node["unicastAddress"], base=16)+1
            else:
                log.error("thiết bị đã tồn tại")
                self.res_error = {self.tp: "add_device",
                                  self.pl: {"status": "01"}}
                self.status_fb = True
                return

        unicast = str("%0.4X" % unicast)

        if (len(data_sigMesh["networkExclusions"]) > 0):
            for i in range(len(data_sigMesh["networkExclusions"])):
                if (len(data_sigMesh["networkExclusions"][i]["addresses"]) > 0):
                    umax = 0
                    for node in data_sigMesh["networkExclusions"][i]["addresses"]:
                        u = int(node, base=16)
                        if u > umax:
                            umax = u
                    if int(unicast, base=16) <= umax:
                        unicast = umax+1
                        unicast = str("%0.4X" % unicast)
                        # if node == unicast:
                        #     unicast = int(node, base=16)+1
                        #     unicast = str("%0.4X" % unicast)

        dat = {"context": 0, "netkey index": 0,
               "uuid": uuid, "address": unicast}
        self.request("provisioning", json.dumps(dat))

    def onoff_device(self, unicastAddress, status):
        """
            on/off thiết bị ble 
                - unicastAddress(hex string 2 byte): địa chỉ thiết bị 
                - status(bool): trạng thái on/off 
                    + False: off
                    + True: on
            ví dụ: 
                onoff_device("0001",1) --> bật thiết bị có địa chỉ 0001
                onoff_device("0001",0) --> tắt thiết bị có địa chỉ 0001
        """
        if status:
            ttl = random.randrange(255)
            ttl = str("%0.2X" % ttl)
            msg = "01"+ttl
        else:
            ttl = random.randrange(255)
            ttl = str("%0.2X" % ttl)
            msg = "00"+ttl
        dat = {"address": unicastAddress, "opcode": "8202", "message": msg}
        self.request("app_data", json.dumps(dat))

    def lightness_device(self, unicastAddress, value):
        """
            độ sáng đèn
                - unicastAddress(hex string 2 byte): địa chỉ thiết bị 
                - value(int): độ sáng đèn 0->100%

            ví dụ: 
                lightness_device("0001",50) --> đèn 0001 sáng 50%
        """
        val = value*65535/100
        ttl = random.randrange(255)
        ttl = str("%0.2X" % ttl)
        msg = str("%0.4X" % int(val))
        msg1 = msg[2] + msg[3] + msg[0] + msg[1] + ttl
        dat = {"address": unicastAddress, "opcode": "824C", "message": msg1}
        self.request("app_data", json.dumps(dat))

    def onoff_group(self, unicastAddress, status):
        """
            on/off thiết bị ble 
                - unicastAddress(hex string 2 byte): địa chỉ thiết bị 
                - status(bool): trạng thái on/off 
                    + False: off
                    + True: on
            ví dụ: 
                onoff_device("0001",1) --> bật thiết bị có địa chỉ 0001
                onoff_device("0001",0) --> tắt thiết bị có địa chỉ 0001
        """
        if status:
            ttl = random.randrange(255)
            ttl = str("%0.2X" % ttl)
            msg = "01"+ttl
        else:
            ttl = random.randrange(255)
            ttl = str("%0.2X" % ttl)
            msg = "00"+ttl
        dat = {"address": unicastAddress, "opcode": "8202", "message": msg}
        self.request("app_data", json.dumps(dat))

    def lightness_group(self, unicastAddress, value):
        """
            độ sáng đèn
                - unicastAddress(hex string 2 byte): địa chỉ thiết bị 
                - value(int): độ sáng đèn 0->100%

            ví dụ: 
                lightness_device("0001",50) --> đèn 0001 sáng 50%
        """
        val = value*65535/100
        ttl = random.randrange(255)
        ttl = str("%0.2X" % ttl)
        msg = str("%0.4X" % int(val))
        msg1 = msg[2] + msg[3] + msg[0] + msg[1] + ttl
        dat = {"address": unicastAddress, "opcode": "824C", "message": msg1}
        self.request("app_data", json.dumps(dat))

    def bindKey(self, unicast):
        dat = {"unicast": unicast, "netkey index": "0000", "appkey index": "0000"}
        self.request(
            "appkey_bind", json.dumps(dat), NUMBER_REPEAT, TIME_REPEAT)

    def composition(self, unicast):
        dat = {"unicast": unicast}
        self.request(
            "composition", json.dumps(dat), NUMBER_REPEAT, TIME_REPEAT)

    def delete_network(self):
        self.request("mesh_clear", "")

    def delete_node(self, unicastAddress):
        dat = {"unicast": unicastAddress}
        # log.debug(dat)
        self.request("delete_node", json.dumps(dat))

    def creat_group(self, name):
        f = open(url_sigMesh_db, "r")
        data_sigMesh = json.loads(f.read())
        f.close()
        unicast = "C000"
        int_unicast = int(unicast, base=16)
        group_list = []
        group_list = list(data_sigMesh["groups"]).copy()
        for group in data_sigMesh["groups"]:
            if group["name"] != name:
                if int(group["address"], base=16) >= int_unicast:
                    int_unicast = int(group["address"], base=16)+1
            else:
                self.res_error = {self.tp: "creat_group",
                                  self.pl: {"status": "01"}}
                # self.res_error[self.tp] = "creat_group"
                # self.res_error[self.pl]["status"] = "01"
                self.status_fb = True
                log.error("group đã tồn tại")
                return

        unicast = str("%0.4X" % int_unicast)
        dat = {
            "name": name,
            "address": unicast,
            "parentAddress": "0000"
        }
        group_list.append(dat)
        data_sigMesh["groups"] = group_list
        f = open(url_sigMesh_db, "w")
        f.write(json.dumps(data_sigMesh, indent=4))
        f.close()
        dat2 = {"address": unicast}
        self.request("addr_publication_add", json.dumps(dat2))
        self.res_error = {self.tp: "creat_group",
                          self.pl: {"status": "00", "name": name, "address": unicast}}
        # self.res_error[self.tp] = "creat_group"
        # self.res_error[self.pl]["status"] = "00"
        # self.res_error[self.pl]["name"] = name
        # self.res_error[self.pl]["address"] = unicast
        self.status_fb = True

    def add_group(self, address_device, address_group):
        f = open(url_sigMesh_db, "r")
        data_sigMesh = json.loads(f.read())
        f.close()
        self.models_device_sub = []
        for node in data_sigMesh["nodes"]:
            if node["unicastAddress"] == address_device:
                for model in node["elements"][0]["models"]:
                    self.models_device_sub.append(model["modelId"])

        dat = {
            "unicast": address_device,
            "elementAddress": address_device,
            "modelIdentifier": self.models_device_sub[0],
            "subscribeAddress": address_group
        }
        del self.models_device_sub[0]
        self.models_device_sub_unicast = address_device
        self.models_device_sub_address_group = address_group
        self.handle = "config_subscribe_model_add"
        self.request("config_subscribe_model_add", json.dumps(dat))

    def remove_group(self, address_device, address_group):
        f = open(url_sigMesh_db, "r")
        data_sigMesh = json.loads(f.read())
        f.close()
        self.models_device_sub_remove = []
        for node in data_sigMesh["nodes"]:
            if node["unicastAddress"] == address_device:
                for model in node["elements"][0]["models"]:
                    self.models_device_sub_remove.append(model["modelId"])
        # log.debug(self.models_device_sub_remove)
        if len(self.models_device_sub_remove) > 0:
            dat = {
                "unicast": address_device,
                "elementAddress": address_device,
                "modelIdentifier": self.models_device_sub_remove[0],
                "subscribeAddress": address_group
            }
            del self.models_device_sub_remove[0]
            self.models_device_sub_remove_unicast = address_device
            self.models_device_sub_remove_address_group = address_group
            self.handle = "config_subscribe_model_delete"
            self.request("config_subscribe_model_delete", json.dumps(dat))

    def delete_group(self, addressGroup):
        f = open(url_sigMesh_db, "r")
        data_sigMesh = json.loads(f.read())
        f.close()

        group_list = []
        group_list = list(data_sigMesh["groups"]).copy()
        st = False
        for group in data_sigMesh["groups"]:
            if group["address"] == addressGroup:
                st = True
                address = group["address"]
                group_list.remove(group)

        data_sigMesh["groups"] = group_list
        f = open(url_sigMesh_db, "w")
        f.write(json.dumps(data_sigMesh, indent=4))
        f.close()
        self.res_error = {self.tp: "",
                          self.pl: {}}
        self.res_error[self.tp] = "delete_group"
        self.res_error[self.pl]["status"] = "01"
        if st:
            self.res_error[self.pl]["status"] = "00"

            dat = {"address": address}
            self.request("addr_publication_remove",
                         json.dumps(dat))
        self.status_fb = True

    def send_public(self):

        f = open(url_sigMesh_db, "r")
        data_sigMesh = json.loads(f.read())
        f.close()
        self.handle = "send_public"
        self.addr_sendPublic = []
        for node in data_sigMesh["nodes"]:
            self.addr_sendPublic.append(node["unicastAddress"])
        for group in data_sigMesh["groups"]:
            self.addr_sendPublic.append(group["address"])

        del self.addr_sendPublic[0]
        if (len(self.addr_sendPublic) > 0):
            dat = {"address": self.addr_sendPublic[0]}
            self.request("addr_publication_add",
                         json.dumps(dat))
            del self.addr_sendPublic[0]

        else:
            self.send_deviceKey()

    def send_deviceKey(self):
        f = open(url_sigMesh_db, "r")
        data_sigMesh = json.loads(f.read())
        f.close()
        self.handle = "send_deviceKey"
        self.addr_sendDeviceKey = []
        for node in data_sigMesh["nodes"]:
            dat = {
                "addr": node["unicastAddress"],
                "key": node["deviceKey"]
            }
            self.addr_sendDeviceKey.append(dat)
        # log.debug(self.addr_sendDeviceKey)
        del self.addr_sendDeviceKey[0]
        if (len(self.addr_sendDeviceKey) > 0):
            for i in range(len(self.addr_sendDeviceKey)):
                if len(self.addr_sendDeviceKey[i]["key"]) == 32:
                    dat = {"key": self.addr_sendDeviceKey[i]["key"],
                           "unicast": self.addr_sendDeviceKey[i]["addr"]}
                    self.request(
                        "devkey_add", json.dumps(dat))
                    del self.addr_sendDeviceKey[i]
                    break
                # else:
                #     del self.addr_sendDeviceKey[0]

    def send_config(self):
        f = open(url_sigMesh_db, "r")
        data_sigMesh = json.loads(f.read())
        f.close()
        localunicasst = data_sigMesh["provisioners"][0]["allocatedUnicastRange"][0]["highAddress"]
        nk = data_sigMesh["netKeys"][0]["key"]
        ak = data_sigMesh["appKeys"][0]["key"]
        try:
            tp = "config"
            pl = {"local unicast": localunicasst,
                  "netkey": [nk], "appkey": [ak]}
            self.request(tp, json.dumps(pl))
        except:
            pass

    def get_iv(self):
        self.request("get_iv", "")

    def red_iv(self):
        self.request("red_iv", "")

    def uartWrite(self, data):
        """send data to uart"""
        if data != None:
            # log.info("send data to uart: %s", data)
            data = bytes.fromhex(data)
            self.serial.write(bytearray(data))
            self.serial.flush()

    def uartRead(self):
        try:
            tmp = bytearray([])
            tmp = bytearray(self.serial.read())
            tmp_len = len(tmp)
            if tmp_len > 0:
                pkt_len = tmp[0]
                if (pkt_len > 1):
                    tmp += bytearray(self.serial.read(pkt_len))
                    # log.debug(tmp)
                    return tmp
        except:
            log.error("error read uart")
            # self.serial.close()
            # exit(0)

    def request(self, topic, payload, num_repeat=0, timout=0):
        """data gửi qua uart"""
        try:
            # log.info("request with: \n \t topic %s \n \t payload: %s", topic, payload)
            if topic == "mesh_clear":
                data_w = dev_req.mesh_clear()
                if data_w != None:
                    self.uartWrite(data_w)

            elif topic == "config":
                try:
                    payload = json.loads(payload)
                    self.local_unicast = payload['local unicast']
                    self.netkey = payload['netkey'][0]
                    self.appkey = payload['appkey'][0]
                except:
                    self.res_error = {self.tp: "",
                                      self.pl: {}}
                    self.res_error[self.tp] = "config"
                    self.res_error[self.pl]["status"] = "ERROR"
                    self.status_fb = True
                    return
                self.uartWrite(dev_req.set_keypair())

            elif topic == "get_iv":
                data_w = dev_req.get_iv()
                if data_w != None:
                    self.uartWrite(data_w)

            elif topic == "delete_node":
                try:
                    payload = json.loads(payload)
                    self.deleteNode_unicast = payload["unicast"]
                    f = open(url_config_db, "r")
                    data_f = json.loads(f.read())
                    f.close()
                    addr_Handle = data_f["addrPublication"][self.deleteNode_unicast]
                    dev_Handle = data_f["deviceKey"][self.deleteNode_unicast]
                except:
                    self.res_error = {self.tp: "",
                                      self.pl: {}}
                    self.res_error[self.tp] = "delete_node"
                    self.res_error[self.pl]["status"] = "ERROR"
                    self.status_fb = True
                    return
                data_w = dev_req.delete_node(addr_Handle, dev_Handle)
                if data_w != None:
                    self.uartWrite(data_w)
                    f = open(url_sigMesh_db, "r")
                    data_sigMesh = json.loads(f.read())
                    f.close()

                    networkExclusions = []
                    networkExclusions = list(
                        data_sigMesh["networkExclusions"][0]["addresses"]).copy()
                    if self.deleteNode_unicast not in networkExclusions:
                        networkExclusions.append(self.deleteNode_unicast)
                    data_sigMesh["networkExclusions"][0]["addresses"] = networkExclusions

                    dataNode = []
                    dataNode = list(data_sigMesh["nodes"]).copy()
                    # log.debug(data_sigMesh["nodes"])
                    for node in data_sigMesh["nodes"]:
                        # log.debug(node)
                        if node["unicastAddress"] == self.deleteNode_unicast:
                            dataNode.remove(node)
                            data_sigMesh["nodes"] = dataNode
                            break
                    # log.debug(data_sigMesh["nodes"])
                    f = open(url_sigMesh_db, "w")
                    f.write(json.dumps(data_sigMesh, indent=4))
                    f.close()

            elif topic == "red_iv":
                file = open(url_config_db)
                data_file = file.read()
                file.close()
                data_json = json.loads(data_file)
                try:
                    pre_Seqnum = data_json["Seqnum"]
                except:
                    pre_Seqnum = 0

                seqnum = int(pre_Seqnum) + 512
                if (seqnum >= 0xFFFFFF00):
                    seqnum = 512

                str_Seqnum = str("%0.8X" % seqnum)
                try:
                    indexIV = data_json["indexIV"]
                except:
                    indexIV = "00000000"

                data_json["Seqnum"] = seqnum
                file = open(url_config_db, 'w')
                file.write(json.dumps(data_json, indent=4))
                file.close()

                data_w = dev_req.red_iv(indexIV, str_Seqnum)
                if data_w != None:
                    self.uartWrite(data_w)

            elif topic == "get_local_unicast":
                self.uartWrite(dev_req.get_local_unicast())

            elif topic == "addr_subscription_add":
                try:
                    payload = json.loads(payload)
                    self.addr_subscription = payload['address']
                except:
                    self.res_error = {self.tp: "",
                                      self.pl: {}}
                    self.res_error[self.tp] = "addr_subscription_add"
                    self.res_error[self.pl]["status"] = "ERROR"
                    self.status_fb = True
                    return
                self.uartWrite(dev_req.add_addrSubscription(
                    self.addr_subscription))

            elif topic == "addr_subscription_remove":
                try:
                    payload = json.loads(payload)
                    self.addr_subscription = payload['address']

                    f = open(url_config_db, "r")
                    data_f = json.loads(f.read())
                    f.close()
                    self.addr_subscription_remove = data_f["addrSubscription"][self.addr_subscription]
                except:
                    self.res_error = {self.tp: "",
                                      self.pl: {}}
                    self.res_error[self.tp] = "addr_subscription_remove"
                    self.res_error[self.pl]["status"] = "ERROR"
                    self.status_fb = True
                    return
                self.uartWrite(dev_req.remove_addrSubscription(
                    self.addr_subscription_remove))

            elif topic == "addr_publication_add":
                try:
                    payload = json.loads(payload)
                    self.addr_publication = payload['address']

                except:
                    self.res_error = {self.tp: "",
                                      self.pl: {}}
                    self.res_error[self.tp] = "addr_publication_add"
                    self.res_error[self.pl]["status"] = "ERROR"
                    self.status_fb = True
                    return
                data_w = dev_req.add_addrPublication(self.addr_publication)
                self.uartWrite(data_w)

            elif topic == "addr_publication_remove":
                try:

                    payload = json.loads(payload)
                    self.addr_publication = payload['address']
                    f = open(url_config_db, "r")
                    data_f = json.loads(f.read())
                    f.close()
                    self.addr_publication_remove = data_f["addrPublication"][self.addr_publication]

                except:
                    self.res_error = {self.tp: "",
                                      self.pl: {}}
                    self.res_error[self.tp] = "addr_publication_remove"
                    self.res_error[self.pl]["status"] = "ERROR"
                    self.status_fb = True
                    return
                self.uartWrite(dev_req.remove_addrPublication(
                    self.addr_publication_remove))

            elif topic == "app_data":
                try:
                    payload = json.loads(payload)
                    self.app_data_addr = payload['address']
                    f = open(url_config_db, "r")
                    data_f = json.loads(f.read())
                    f.close()
                    self.DST_Addr_Handle = data_f["addrPublication"][self.app_data_addr]

                    self.opcode = payload['opcode']
                    self.message = payload['message']

                    data = self.opcode+self.message
                except:
                    self.res_error = {self.tp: "",
                                      self.pl: {}}
                    self.res_error[self.tp] = "app_data"
                    self.res_error[self.pl]["status"] = "ERROR"
                    self.status_fb = True
                    return
                self.uartWrite(dev_req.send_meshPacket(
                    self.DST_Addr_Handle, data))

            elif topic == "scanStart":
                self.uartWrite(dev_req.scanStart())
            elif topic == "scanStop":
                self.uartWrite(dev_req.scanStop())
            elif topic == "provisioning":

                try:

                    payload = json.loads(payload)
                    context = payload['context']
                    netkeyIndex = payload['netkey index']
                    uuid = payload['uuid']
                    address = payload['address']

                    f = open(url_sigMesh_db, "r")
                    data_sigMesh = json.loads(f.read())
                    f.close()

                    data_sigMesh_nodes = []
                    data_sigMesh_nodes = list(data_sigMesh["nodes"]).copy()

                    data_sigMesh_nodes_prov = {
                        "UUID": uuid,
                        "name": self.prov_deviceName,
                        "deviceKey": "A36B6C4BD62EF47466A2EBB7584DC1A1",
                        "unicastAddress": address,
                        "security": "insecure",
                                    "configComplete": False,
                                    "features": {
                                        "friend": 2,
                                        "lowPower": 2,
                                        "proxy": 2,
                                        "relay": 2
                                    },
                        "defaultTTL": 5,
                        "netKeys": [
                                        {
                                            "index": 0,
                                            "updated": False
                                        }
                                    ],
                        "appKeys": [
                                        {
                                            "index": 0,
                                            "updated": False
                                        },
                                        {
                                            "index": 1,
                                            "updated": False
                                        },
                                        {
                                            "index": 2,
                                            "updated": False
                                        }
                                    ],
                        "elements": [
                                        {
                                            "name": "Element: 0x0001",
                                            "index": 0,
                                            "location": "0000",
                                            "models": [
                                                {
                                                    "modelId": "0001",
                                                    "bind": [],
                                                    "subscribe": []
                                                }
                                            ]
                                        }
                                    ],
                        "excluded": False
                    }

                    # data_sigMesh_nodes_prov = {
                    #     "appKeys": [
                    #         {
                    #             "index": "",
                    #             "updated": False
                    #         }
                    #     ],
                    #     "cid": "",
                    #     "configComplete": True,
                    #     "crpl": "",
                    #     "deviceKey": "",
                    #     "elements": [
                    #             {
                    #                 "index": "",
                    #                 "location": "",
                    #                 "models": [
                    #                     {
                    #                         "bind": [

                    #                         ],
                    #                         "modelId": "0000",
                    #                         "subscribe": [

                    #                         ]
                    #                     }
                    #                 ],
                    #                 "name": "Primary Element"
                    #             },

                    #     ],
                    #     "excluded": False,
                    #     "features": {
                    #         "friend": "",
                    #         "lowPower": "",
                    #         "proxy": "",
                    #         "relay": ""
                    #     },
                    #     "name": self.prov_deviceName,
                    #     "netKeys": [
                    #         {
                    #             "index": "",
                    #             "updated": False
                    #         }
                    #     ],
                    #     "security": "secure",
                    #     "unicastAddress": address,
                    #     "UUID": uuid
                    # }

                    data_sigMesh_nodes.append(data_sigMesh_nodes_prov)
                    data_sigMesh["nodes"] = data_sigMesh_nodes
                    f = open(url_sigMesh_db, "w")
                    f.write(json.dumps(data_sigMesh, indent=4))
                    f.close()
                except:
                    self.res_error = {self.tp: "",
                                      self.pl: {}}
                    self.res_error[self.tp] = "provisioning"
                    self.res_error[self.pl]["status"] = "ERROR"
                    self.status_fb = True
                    return
                self.uartWrite(dev_req.Provisioning(
                    context, uuid, netkeyIndex, address))

            elif topic == "prov_listen":
                self.uartWrite(dev_req.prov_listen())

            elif topic == "provisioningOOBUse":
                try:
                    payload = json.loads(payload)
                    context = payload['context']

                except:
                    self.res_error = {self.tp: "",
                                      self.pl: {}}
                    self.res_error[self.tp] = "provisioningOOBUse"
                    self.res_error[self.pl]["status"] = "ERROR"
                    self.status_fb = True
                    return
                self.uartWrite(dev_req.provisioningOOBUse(
                    context))
            # elif topic == "provECDHSecret":
            #     self.uartWrite(dev_req.provisioningECDHSecret())

            elif topic == "devkey_delete":
                try:
                    payload = json.loads(payload)
                    self.addr_devkey_remove = payload['address']

                    f = open(url_config_db, "r")
                    data_f = json.loads(f.read())
                    f.close()
                    self.addr_devkeyHandle_remove = data_f["deviceKey"][self.addr_devkey_remove]
                except:
                    self.res_error = {self.tp: "",
                                      self.pl: {}}
                    self.res_error[self.tp] = "devkey_delete"
                    self.res_error[self.pl]["status"] = "ERROR"
                    self.status_fb = True
                    return
                self.uartWrite(dev_req.devkey_delete(
                    self.addr_devkeyHandle_remove))

            elif topic == "appkey_bind":
                # log.debug("send appkey_bind")

                try:
                    payload = json.loads(payload)
                    f = open(url_config_db, "r")
                    data_f = json.loads(f.read())
                    f.close()
                    self.appkey_bind_unicast = payload["unicast"]
                    self.appkey_bind_netKeyIndex = payload['netkey index']
                    self.appkey_bind_appKeyIndex = payload['appkey index']
                    if (self.appkey_bind_appKeyIndex == "0000"):
                        self.appkey_bind_appKey = data_f["config"]["appkey"]
                    else:
                        self.appkey_bind_appKey = payload['appkey']
                    self.appkey_bind_addrHandle = data_f["addrPublication"][self.appkey_bind_unicast]
                    self.appkey_bind_addrDevkeyHandle = data_f["deviceKey"][self.appkey_bind_unicast]
                except Exception as e:
                    self.res_error = {self.tp: "",
                                      self.pl: {}}
                    self.res_error[self.tp] = "appkey_bind"
                    self.res_error[self.pl]["status"] = "ERROR"
                    self.status_fb = True
                    return
                data_w = dev_req.appkey_bind(self.appkey_bind_netKeyIndex, self.appkey_bind_appKeyIndex,
                                             self.appkey_bind_appKey, self.appkey_bind_addrHandle, self.appkey_bind_addrDevkeyHandle)
                if num_repeat > 0:
                    self.tpRepeat = "appkey_bind"
                    self.repeat = data_w
                    self.num_repeat = num_repeat
                    self.timeout = timout
                    self.time = time.time()
                self.uartWrite(data_w)

            elif topic == "composition":
                try:
                    payload = json.loads(payload)
                    f = open(url_config_db, "r")
                    data_f = json.loads(f.read())
                    f.close()
                    self.composition_unicast = payload['unicast']
                    composition_addrHandle = data_f["addrPublication"][self.composition_unicast]
                    composition_addrDevkeyHandle = data_f["deviceKey"][self.composition_unicast]
                except:
                    self.res_error = {self.tp: "",
                                      self.pl: {}}
                    self.res_error[self.tp] = "composition"
                    self.res_error[self.pl]["status"] = "ERROR"
                    self.status_fb = True
                    return
                data_w = dev_req.composition(
                    composition_addrHandle, composition_addrDevkeyHandle)
                if num_repeat > 0:
                    self.tpRepeat = "composition"
                    self.repeat = data_w
                    self.num_repeat = num_repeat
                    self.timeout = timout
                    self.time = time.time()
                self.uartWrite(data_w)
            elif topic == "devkey_add":
                try:
                    payload = json.loads(payload)
                    f = open(url_config_db, "r")
                    data_f = json.loads(f.read())
                    f.close()
                    self.devkey_add_unicast = payload['unicast']

                    self.devkey_add_key = payload['key']
                    self.devkey_add_addrHandle = data_f["addrPublication"][self.devkey_add_unicast]
                    self.uartWrite(dev_req.add_devkey(
                        self.devkey_add_unicast, self.devkey_add_addrHandle, self.devkey_add_key))
                except:
                    # log.info("loi")
                    self.res_error = {self.tp: "",
                                      self.pl: {}}
                    self.res_error[self.tp] = "devkey_add"
                    self.res_error[self.pl]["status"] = "ERROR"
                    # log.error(payload)
                    self.status_fb = True

            elif topic == "config_subscribe_model_add":
                try:
                    payload = json.loads(payload)
                    f = open(url_config_db, "r")
                    data_f = json.loads(f.read())
                    f.close()
                    self.config_subscribe_model_add_unicast = payload['unicast']
                    self.config_subscribe_model_add_elementAddress = payload['elementAddress']
                    self.config_subscribe_model_add_modelIdentifier = payload['modelIdentifier']
                    # log.debug("sub model: %s",
                    #           self.config_subscribe_model_add_modelIdentifier)
                    self.config_subscribe_model_add_subscribeAddress = payload['subscribeAddress']

                    addrHandle = data_f[
                        "addrPublication"][self.config_subscribe_model_add_unicast]
                    devHandle = data_f[
                        "deviceKey"][self.config_subscribe_model_add_unicast]

                    data_w = dev_req.config_subscribe_model_add(addrHandle, devHandle,
                                                                self.config_subscribe_model_add_elementAddress,
                                                                self.config_subscribe_model_add_subscribeAddress,
                                                                self.config_subscribe_model_add_modelIdentifier)
                    # log.debug(data_w)
                    if num_repeat > 0:
                        self.tpRepeat = "config_subscribe_model_add"
                        self.repeat = data_w
                        self.num_repeat = num_repeat
                        self.timeout = timout
                        self.time = time.time()
                    self.uartWrite(data_w)
                except:
                    # log.info("loi")
                    self.res_error = {self.tp: "",
                                      self.pl: {}}
                    self.res_error[self.tp] = "config_subscribe_model_add"
                    self.res_error[self.pl]["status"] = "ERROR"
                    # log.error(payload)
                    self.status_fb = True
                    # return

            elif topic == "config_subscribe_model_delete":
                try:
                    payload = json.loads(payload)
                    f = open(url_config_db, "r")
                    data_f = json.loads(f.read())
                    f.close()
                    config_subscribe_model_delete_unicast = payload['unicast']
                    config_subscribe_model_delete_elementAddress = payload['elementAddress']
                    config_subscribe_model_delete_modelIdentifier = payload['modelIdentifier']
                    # log.debug("delete model: %s",
                    #           config_subscribe_model_delete_modelIdentifier)
                    config_subscribe_model_delete_subscribeAddress = payload['subscribeAddress']

                    addrHandle = data_f[
                        "addrPublication"][config_subscribe_model_delete_unicast]
                    devHandle = data_f[
                        "deviceKey"][config_subscribe_model_delete_unicast]

                    data_w = dev_req.config_subscribe_model_delete(addrHandle, devHandle,
                                                                   config_subscribe_model_delete_elementAddress,
                                                                   config_subscribe_model_delete_subscribeAddress,
                                                                   config_subscribe_model_delete_modelIdentifier)
                    # log.debug(data_w)
                    if num_repeat > 0:
                        self.tpRepeat = "config_subscribe_model_delete"
                        self.repeat = data_w
                        self.num_repeat = num_repeat
                        self.timeout = timout
                        self.time = time.time()
                    self.uartWrite(data_w)
                except:
                    self.res_error = {self.tp: "",
                                      self.pl: {}}
                    self.res_error[self.tp] = "config_subscribe_model_delete"
                    self.res_error[self.pl]["status"] = "ERROR"
                    # log.error(payload)
                    self.status_fb = True
                    # return

            elif topic == "bind_key_model":

                try:
                    payload = json.loads(payload)
                    f = open(url_config_db, "r")
                    data_f = json.loads(f.read())
                    f.close()
                    self.bind_key_model_unicast = payload['unicast']
                    self.bind_key_model_elementAddress = payload['element address']
                    self.bind_key_model_modelIdentifier = payload['model identifier']
                    # log.debug("bind %s - unicasst: %s",
                    #           self.bind_key_model_modelIdentifier, self.bind_key_model_unicast)
                    self.bind_key_model_appKeyIndex = payload['appKey index']

                    self.bind_key_model_addrHandle = data_f["addrPublication"][self.bind_key_model_unicast]
                    self.bind_key_model_deviceKeyHandle = data_f["deviceKey"][self.bind_key_model_unicast]
                except:
                    self.res_error = {self.tp: "",
                                      self.pl: {}}
                    self.res_error[self.tp] = "bind_key_model"
                    self.res_error[self.pl]["status"] = "ERROR"
                    self.status_fb = True
                    return
                data_w = dev_req.bind_key_model(
                    self.bind_key_model_addrHandle, self.bind_key_model_deviceKeyHandle, self.bind_key_model_elementAddress, self.bind_key_model_appKeyIndex, self.bind_key_model_modelIdentifier)
                if num_repeat > 0:
                    self.tpRepeat = "bind_key_model"
                    self.repeat = data_w
                    self.num_repeat = num_repeat
                    self.timeout = timout
                    self.time = time.time()
                self.uartWrite(data_w)
        except:
            pass

    def event(self):
        if (self.num_repeat > 0) & (self.tpRepeat != None):
            if ((time.time()-self.time) >= self.timeout):
                log.debug("gui lai %s lan %d", self.tpRepeat,
                          (NUMBER_REPEAT-self.num_repeat))
                self.uartWrite(self.repeat)
                self.num_repeat = self.num_repeat-1
                self.time = time.time()
        elif self.tpRepeat != None:
            da = {self.tp: self.tpRepeat, self.pl: {"status": "TIMEOUT"}}
            if self.tpRepeat == "appkey_bind":
                da = {self.tp: self.tpRepeat, self.pl: {
                    "status": "TIMEOUT", "address": self.appkey_bind_unicast}}
            self.tpRepeat = None
            return da

        if self.status_fb:
            try:
                self.res_error = json.dumps(self.res_error)
            except:
                pass
            self.status_fb = False
            return self.res_error

        else:
            tmp = self.uartRead()
            if (tmp != None):
                tmps = dev_res.res(tmp)
                if tmps != None:
                    try:
                        topic = tmps[self.tp]
                        if self.tpRepeat == topic:
                            self.tpRepeat = None
                            self.num_repeat = 0
                        # log.debug(tmps)

                        # set network
                        if topic == "setKeypair":
                            self.set_keypair = tmps
                            self.uartWrite(
                                dev_req.set_local_unicast(self.local_unicast))
                            # log.debug(tmps)
                        elif topic == "setLocalUnicast":
                            self.set_localUnicast = tmps
                            self.uartWrite(
                                self.uartWrite(dev_req.set_netkey(self.netkey)))
                        elif topic == "setNetKey":
                            self.set_netkey = tmps
                            self.uartWrite(
                                self.uartWrite(dev_req.set_appkey(self.appkey)))
                        elif topic == "setAppKey":
                            self.set_appkey = tmps
                            config = {
                                self.tp: "config",
                                self.pl: {
                                    "local unicast": {
                                        "addr": self.local_unicast,
                                        "status": self.set_localUnicast[self.pl]["status"]
                                    },
                                    "netkey": [
                                        {
                                            "key": self.netkey,
                                            "status": self.set_netkey[self.pl]["status"]
                                        }
                                    ],
                                    "appkey": [
                                        {
                                            "key": self.appkey,
                                            "status": self.set_appkey[self.pl]["status"]
                                        }
                                    ]
                                }
                            }
                            f = open(url_config_db, "r")
                            data_f = json.loads(f.read())
                            f.close()
                            try:
                                f = open(url_sigMesh_db, "r")
                                data_sigMesh = json.loads(f.read())
                                f.close()
                            except:
                                log.error("loi read url_sigMesh_db")

                            data_f["config"] = {
                                "local unicast": "",
                                "netkey": "",
                                "appkey": ""
                            }
                            if self.set_localUnicast[self.pl]["status"] == "00":
                                data_f["config"]["local unicast"] = self.local_unicast
                                if self.set_netkey[self.pl]["status"] == "00":
                                    data_f["config"]["netkey"] = self.netkey
                                    data_sigMesh["netKeys"][0]["key"] = self.netkey
                                    if self.set_appkey[self.pl]["status"] == "00":
                                        data_f["config"]["appkey"] = self.appkey
                                        data_sigMesh["appKeys"][0]["key"] = self.appkey
                                        f = open(url_config_db, "w")
                                        f.write(json.dumps(data_f, indent=4))
                                        f.close()
                                        f = open(url_sigMesh_db, "w")
                                        f.write(json.dumps(
                                            data_sigMesh, indent=4))
                                        f.close()
                                        self.send_public()

                            # return json.dumps(config)

                        # add public addr
                        elif topic == "addr_publication_add":
                            if (self.handle == "provision"):
                                if tmps[self.pl]["status"] == "00":
                                    self.prov_public_status = tmps[self.pl]["status"]
                                    self.prov_public_addrHandle = tmps[self.pl]["address"]
                                    self.addr_publication = self.prov_address
                                    self.devkey_add_unicast = self.prov_address

                                    self.uartWrite(dev_req.add_devkey(
                                        self.prov_address, self.prov_public_addrHandle, self.prov_deviceKey))
                                    f = open(url_config_db, "r")
                                    data_f = json.loads(f.read())
                                    f.close()

                                    data_f["addrPublication"][self.addr_publication] = tmps[self.pl]["address"]
                                    f = open(url_config_db, "w")
                                    f.write(json.dumps(data_f, indent=4))
                                    f.close()
                                else:
                                    self.handle = None
                                    fb = {
                                        self.tp: "add_device",
                                        self.pl: {
                                            "name": self.prov_deviceName,
                                            "status": "03"
                                        }
                                    }
                                    return json.dumps(fb)

                            elif (self.handle == "send_public"):

                                f = open(url_config_db, "r")
                                data_f = json.loads(f.read())
                                f.close()
                                data_f["addrPublication"][self.addr_publication] = tmps[self.pl]["address"]
                                f = open(url_config_db, "w")
                                f.write(json.dumps(data_f, indent=4))
                                f.close()

                                if (len(self.addr_sendPublic) > 0):

                                    dat = {"address": self.addr_sendPublic[0]}
                                    self.request("addr_publication_add",
                                                 json.dumps(dat))
                                    del self.addr_sendPublic[0]
                                else:
                                    self.send_deviceKey()

                                # return json.dumps(tmps)

                            else:
                                if tmps[self.pl]["status"] == "00":

                                    f = open(url_config_db, "r")
                                    data_f = json.loads(f.read())
                                    f.close()

                                    data_f["addrPublication"][self.addr_publication] = tmps[self.pl]["address"]
                                    f = open(url_config_db, "w")
                                    f.write(json.dumps(data_f, indent=4))
                                    f.close()

                        elif topic == "addr_publication_remove":
                            f = open(url_config_db, "r")
                            data_f = json.loads(f.read())
                            f.close()

                            data_f["addrPublication"].pop(
                                self.addr_publication)
                            # data_f["addrPublication"][self.addr_publication] = tmps[self.pl]["address"]
                            f = open(url_config_db, "w")
                            f.write(json.dumps(data_f, indent=4))
                            f.close()
                            # return json.dumps(tmps)

                        # add subscript addr
                        elif topic == "addr_subscription_add":
                            f = open(url_config_db, "r")
                            data_f = json.loads(f.read())
                            f.close()

                            data_f["addrSubscription"][self.addr_subscription] = tmps[self.pl]["address"]
                            f = open(url_config_db, "w")
                            f.write(json.dumps(data_f, indent=4))
                            f.close()

                            # return json.dumps(tmps)
                        elif topic == "addr_subscription_remove":
                            f = open(url_config_db, "r")
                            data_f = json.loads(f.read())
                            f.close()

                            data_f["addrSubscription"].pop(
                                self.addr_subscription)
                            f = open(url_config_db, "w")
                            f.write(json.dumps(data_f, indent=4))
                            f.close()
                            # return json.dumps(tmps)

                        # provitioning
                        elif topic == "provision":
                            if tmps[self.pl]["status"] == "00":
                                self.handle = "provision"
                            else:
                                self.handle = None
                                fb = {
                                    self.tp: "add_device",
                                    self.pl: {
                                        "name": self.prov_deviceName,
                                        "status": "01"
                                    }
                                }
                                return json.dumps(fb)

                        elif topic == "prov_capabilities":
                            self.prov_numElements = tmps[self.pl]["numElements"]
                            self.uartWrite(dev_req.prov_listen())

                        elif topic == "provListen":

                            self.uartWrite(dev_req.provisioningOOBUse(0))

                        elif topic == "ECDH_reponst":
                            payload = tmps[self.pl]

                            self.uartWrite(dev_req.provisioningECDHSecret(
                                payload["peerPublic"], payload["nodePrivate"]))

                        elif topic == "provOOBUse":
                            pass
                        elif topic == "provECDHSecret":
                            pass
                        elif topic == "data ack":
                            pass
                        elif topic == "provComplete":
                            self.prov_context = tmps[self.pl]["context"]
                            self.prov_deviceKey = tmps[self.pl]["deviceKey"]
                            self.prov_netKey = tmps[self.pl]["netKey"]
                            self.prov_address = tmps[self.pl]["address"]

                            self.uartWrite(
                                dev_req.add_addrPublication(self.prov_address))
                        elif (topic == "devkey_add"):
                            if self.handle == "provision":
                                if tmps[self.pl]["status"] == "00":
                                    f = open(url_sigMesh_db, "r")
                                    data_sigMesh = json.loads(f.read())
                                    f.close()
                                    data_sigMesh_nodes = []
                                    data_sigMesh_nodes = list(
                                        data_sigMesh["nodes"]).copy()
                                    data_sigMesh_nodes_adr = {}
                                    z = 0
                                    for x in data_sigMesh_nodes:

                                        if x["unicastAddress"] == self.devkey_add_unicast:
                                            data_sigMesh_nodes_adr = x
                                            break
                                        else:
                                            z = z+1
                                    self.prov_devKey_status = tmps[self.pl]["status"]
                                    # self.handle = None
                                    self.prov_devkeyHandle = tmps[self.pl]["devkeyHandle"]
                                    provisioning = {
                                        self.tp: "provisioning",
                                        self.pl: {
                                            "context": self.prov_context,
                                            "number of elements": self.prov_numElements,
                                            "address": self.prov_address,
                                            "network key": self.prov_netKey,
                                            "device key": self.prov_deviceKey,
                                            "devkey addr status": self.prov_devKey_status,
                                            "publish addr status": self.prov_public_status,
                                            "devkey handle": self.prov_devkeyHandle,
                                            "address handle": self.prov_public_addrHandle
                                        }
                                    }
                                    data_sigMesh_nodes_adr["deviceKey"] = self.prov_deviceKey
                                    data_sigMesh_nodes_adr["netKeys"][0]["index"] = 0
                                    data_sigMesh_nodes_adr["appKeys"][0]["index"] = 0
                                    data_sigMesh["nodes"][z] = data_sigMesh_nodes_adr
                                    # log.debug(data_sigMesh)
                                    f = open(url_sigMesh_db, "w")
                                    f.write(json.dumps(
                                        data_sigMesh, indent=4))
                                    f.close()

                                    if self.prov_devKey_status == "00":

                                        f = open(url_config_db, "r")
                                        data_f = json.loads(f.read())
                                        f.close()
                                        data_f["deviceKey"][self.prov_address] = self.prov_devkeyHandle
                                        f = open(url_config_db, "w")
                                        f.write(json.dumps(data_f, indent=4))
                                        f.close()
                                        return
                                else:
                                    self.handle = None
                                    fb = {
                                        self.tp: "add_device",
                                        self.pl: {
                                            "name": self.prov_deviceName,
                                            "status": "04"
                                        }
                                    }
                                    return json.dumps(fb)

                                # return json.dumps(provisioning)
                            elif self.handle == "send_deviceKey":
                                if tmps[self.pl]["status"] == "00":
                                    f = open(url_config_db, "r")
                                    data_f = json.loads(f.read())
                                    f.close()
                                    data_f["deviceKey"][self.devkey_add_unicast] = tmps[self.pl]["devkeyHandle"]
                                    f = open(url_config_db, "w")
                                    f.write(json.dumps(data_f, indent=4))
                                    f.close()

                                if (len(self.addr_sendDeviceKey) > 0):
                                    for i in range(len(self.addr_sendDeviceKey)):
                                        if len(self.addr_sendDeviceKey[i]["key"]) == 32:
                                            dat = {"key": self.addr_sendDeviceKey[i]["key"],
                                                   "unicast": self.addr_sendDeviceKey[i]["addr"]}
                                            self.request(
                                                "devkey_add", json.dumps(dat))
                                            del self.addr_sendDeviceKey[i]
                                            break

                                else:
                                    self.handle = None
                                    self.red_iv()
                                # return json.dumps(tmps)

                        elif (topic == "provClosed"):
                            dat = {"unicast": self.prov_address,
                                   "netkey index": "0000", "appkey index": "0000"}
                            time.sleep(0.5)
                            self.request(
                                "appkey_bind", json.dumps(dat), NUMBER_REPEAT, TIME_REPEAT)

                        elif (topic == "bind_key_model"):
                            # log.debug(tmps)
                            payload = tmps[self.pl]
                            model = payload["model identifier"]
                            # log.debug(self.list_model_bindkey)
                            # log.debug(model)
                            del self.list_model_bindkey[0]
                            # if model in self.list_model_bindkey:
                            #     self.list_model_bindkey.remove(model)
                            if len(self.list_model_bindkey) > 0:
                                dat = {
                                    "unicast": self.bind_key_model_unicast,
                                    "element address": self.bind_key_model_unicast,
                                    "model identifier": self.list_model_bindkey[0],
                                    "appKey index": "0000"
                                }
                                self.request("bind_key_model", json.dumps(
                                    dat), NUMBER_REPEAT, TIME_REPEAT)
                            else:
                                self.handle = None
                                fb = {
                                    self.tp: "add_device",
                                    self.pl: {
                                        "name": self.prov_deviceName,
                                        "status": "00",
                                        "address": self.prov_address
                                    }
                                }
                                return json.dumps(fb)
                            # if payload["model identifier"] == self.modelbind:

                                # self.handle = None
                                # fb = {
                                #     self.tp: "add_device",
                                #     self.pl: {
                                #         "name": self.prov_deviceName,
                                #         "status": "00",
                                #         "address": self.prov_address
                                #     }
                                # }
                                # return json.dumps(fb)

                        elif (topic == "devkey_delete"):
                            if (tmps[self.pl]["status"] == "00"):
                                f = open(url_config_db, "r")
                                data_f = json.loads(f.read())
                                f.close()
                                data_f["deviceKey"].pop(
                                    self.addr_devkey_remove)
                                f = open(url_config_db, "w")
                                f.write(json.dumps(data_f, indent=4))
                                f.close()
                            # return json.dumps(tmps)

                        elif topic == "mesh_clear":
                            data_f = {
                                "addrPublication": {},
                                "addrSubscription": {},
                                "deviceKey": {},
                                "config": {}
                            }
                            f = open(url_config_db, "w")
                            f.write(json.dumps(data_f, indent=4))
                            f.close()

                            new_netkey = ""
                            for i in range(16):
                                b = random.randrange(255)
                                new_netkey += str("%0.2X" % (b))
                            new_appkey = ""
                            for i in range(16):
                                b = random.randrange(255)
                                new_appkey += str("%0.2X" % (b))
                            # C8F9B27A755DAFAE731A25E8C70D296E
                            # DA7DC6A2FB21A5586EB0A08C1BE7FCF3 nk
                            # BF56D55C019D257FC28B6D67F1E40ED2 ak

                            data_sigMesh_clear = {
                                "$schema": "http://json-schema.org/draft-04/schema#",
                                "id": "http://www.bluetooth.com/specifications/assigned-numbers/mesh-profile/cdb-schema.json#",
                                "version": "1.0.0",
                                "meshUUID": "8215F17A-9BA1-4A63-B099-A68A9B3685FA",
                                "meshName": "nRF Mesh Network",
                                "timestamp": "2022-12-08T14:05:02+07:00",
                                "partial": False,
                                "netKeys": [
                                    {
                                        "name": "Network Key 1",
                                        "index": 0,
                                        "key": new_netkey,
                                        "phase": 0,
                                        "minSecurity": "insecure",
                                        "timestamp": "2022-12-08T14:05:02+07:00"
                                    }
                                ],
                                "appKeys": [
                                    {
                                        "name": "Application Key 1",
                                        "index": 0,
                                        "boundNetKey": 0,
                                        "key": new_appkey
                                    }

                                ],
                                "provisioners": [
                                    {
                                        "provisionerName": "nRF Mesh Provisioner",
                                        "UUID": "8BE6C84E-7708-45AA-933B-828628120577",
                                        "allocatedUnicastRange": [
                                            {
                                                "lowAddress": "0001",
                                                "highAddress": "199A"
                                            }
                                        ],
                                        "allocatedGroupRange": [
                                            {
                                                "lowAddress": "C000",
                                                "highAddress": "CC9A"
                                            }
                                        ],
                                        "allocatedSceneRange": [
                                            {
                                                "firstScene": "0001",
                                                "lastScene": "3333"
                                            }
                                        ]
                                    }
                                ],
                                "nodes": [
                                    {
                                        "UUID": "8BE6C84E-7708-45AA-933B-828628120577",
                                        "name": "nRF Mesh Provisioner",
                                        "deviceKey": "A36B6C4BD62EF47466A2EBB7584DC1A1",
                                        "unicastAddress": "0001",
                                        "security": "insecure",
                                        "configComplete": False,
                                        "features": {
                                            "friend": 2,
                                            "lowPower": 2,
                                            "proxy": 2,
                                            "relay": 2
                                        },
                                        "defaultTTL": 5,
                                        "netKeys": [
                                            {
                                                "index": 0,
                                                "updated": False
                                            }
                                        ],
                                        "appKeys": [
                                            {
                                                "index": 0,
                                                "updated": False
                                            },
                                            {
                                                "index": 1,
                                                "updated": False
                                            },
                                            {
                                                "index": 2,
                                                "updated": False
                                            }
                                        ],
                                        "elements": [
                                            {
                                                "name": "Element: 0x0001",
                                                "index": 0,
                                                "location": "0000",
                                                "models": [
                                                    {
                                                        "modelId": "0001",
                                                        "bind": [],
                                                        "subscribe": []
                                                    }
                                                ]
                                            }
                                        ],
                                        "excluded": False
                                    }
                                ],
                                "groups": [],
                                "scenes": [],
                                "networkExclusions": [
                                    {
                                        "ivIndex": 0,
                                        "addresses": []
                                    }
                                ]
                            }

                            f = open(url_sigMesh_db, "w")
                            f.write(json.dumps(data_sigMesh_clear, indent=4))
                            f.close()
                            self.send_config()
                            fb = {
                                self.tp: "delete_network",
                                self.pl: {

                                    "status": "00"
                                }
                            }
                            return json.dumps(fb)

                            # return json.dumps(tmps)

                        elif topic == "appkey_bind":
                            tmps[self.pl]["unicast"] = self.appkey_bind_unicast
                            if self.tpRepeat == topic:
                                self.tpRepeat = None
                                self.num_repeat = 0
                            if self.handle == "provision":
                                if tmps[self.pl]["status"] == "00":

                                    dat = {"unicast": "0000"}
                                    dat["unicast"] = self.appkey_bind_unicast
                                    self.request(
                                        "composition", json.dumps(dat), NUMBER_REPEAT, TIME_REPEAT)
                                else:
                                    self.handle = None
                                    fb = {
                                        self.tp: "add_device",
                                        self.pl: {
                                            "name": self.prov_deviceName,
                                            "status": "05"
                                        }
                                    }
                                    return json.dumps(fb)
                            else:
                                if tmps[self.pl]["status"] == "00":

                                    dat = {"unicast": "000C"}
                                    dat["unicast"] = self.appkey_bind_unicast
                                    self.request(
                                        "composition", json.dumps(dat))
                                return json.dumps(tmps)

                        elif topic == "composition":
                            tmps[self.pl]["unicast"] = self.composition_unicast
                            payload = tmps[self.pl]
                            self.bind_key_model_unicast = payload["unicast"]
                            try:
                                f = open(url_config_db, "r")
                                data_f = json.loads(f.read())
                                f.close()
                                self.bind_key_model_unicast = payload['unicast']

                                self.bind_key_model_appKeyIndex = "0000"

                                self.bind_key_model_addrHandle = data_f[
                                    "addrPublication"][self.bind_key_model_unicast]
                                self.bind_key_model_deviceKeyHandle = data_f[
                                    "deviceKey"][self.bind_key_model_unicast]
                            except:
                                self.res_error = {self.tp: "",
                                                  self.pl: {}}
                                self.res_error[self.tp] = "bind_key_all_model"
                                self.res_error[self.pl]["status"] = "ERROR"
                                self.status_fb = True
                                return

                            # save file
                            f = open(url_sigMesh_db, "r")
                            data_sigMesh = json.loads(f.read())
                            f.close()
                            data_sigMesh_nodes = []
                            data_sigMesh_nodes = list(
                                data_sigMesh["nodes"]).copy()

                            data_sigMesh_nodes_adr = {}
                            z = 0
                            for x in data_sigMesh_nodes:
                                if x["unicastAddress"] == self.devkey_add_unicast:
                                    data_sigMesh_nodes_adr = x
                                    break
                                else:
                                    z = z+1

                            data_sigMesh_nodes_adr["elements"] = payload["elements"]
                            l = 0
                            for x in payload["elements"]:
                                self.bind_key_model_elementAddress = str("%0.4X" % (
                                    int(self.bind_key_model_unicast, 16) + x["index"]))
                                # self.data_sigMesh_nodes_prov["appKeys"][0]["index"] = 0
                                k = 0
                                self.list_model_bindkey = []
                                for y in x["models"]:
                                    self.list_model_bindkey.append(y)
                                    self.bind_key_model_modelIdentifier = y

                                    # self.uartWrite(dev_req.bind_key_model(
                                    #     self.bind_key_model_addrHandle, self.bind_key_model_deviceKeyHandle, self.bind_key_model_elementAddress, self.bind_key_model_appKeyIndex, self.bind_key_model_modelIdentifier))
                                    # time.sleep(0.2)
                                    data_sigMesh_nodes_adr["elements"][l]["models"][k] = {
                                        "bind": [0],
                                        "modelId": y,
                                        "subscribe": []
                                    }
                                    k = k+1
                                self.modelbind = self.bind_key_model_modelIdentifier
                                l = l+1

                            data_sigMesh_nodes_adr["cid"] = payload["cid"]
                            data_sigMesh_nodes_adr["pid"] = payload["pid"]
                            data_sigMesh_nodes_adr["vid"] = payload["vid"]
                            data_sigMesh_nodes_adr["crpl"] = payload["crpl"]

                            data_sigMesh_nodes_adr["features"]["friend"] = payload["friends"]
                            data_sigMesh_nodes_adr["features"]["lowPower"] = payload["low power"]
                            data_sigMesh_nodes_adr["features"]["proxy"] = payload["proxy"]
                            data_sigMesh_nodes_adr["features"]["relay"] = payload["relay"]

                            data_sigMesh["nodes"][z] = data_sigMesh_nodes_adr
                            f = open(url_sigMesh_db, "w")
                            f.write(json.dumps(
                                data_sigMesh, indent=4))
                            f.close()
                            if len(self.list_model_bindkey) > 0:
                                dat = {
                                    "unicast": self.bind_key_model_unicast,
                                    "element address": self.bind_key_model_unicast,
                                    "model identifier": self.list_model_bindkey[0],
                                    "appKey index": "0000"
                                }
                                self.request("bind_key_model", json.dumps(
                                    dat), NUMBER_REPEAT, TIME_REPEAT)
                            # return json.dumps(tmps)

                        elif (topic == "onOffStatus"):
                            payload = tmps[self.pl]
                            if len(tmps[self.pl]["p"]) == 2:
                                if tmps[self.pl]["p"] == "00":
                                    status = "OFF"
                                else:
                                    status = "ON"
                            elif len(tmps[self.pl]["p"]) == 6:
                                if tmps[self.pl]["p"][3] == "0":
                                    status = "OFF"
                                else:
                                    status = "ON"
                            feedback = {
                                self.tp: "onOffStatus",
                                self.pl: {
                                    "address": tmps[self.pl]["a"],
                                    "status": status
                                }
                            }
                            return json.dumps(feedback)

                        elif (topic == "lightnessStatus"):
                            payload = tmps[self.pl]

                            ln = int(tmps[self.pl]["p"], base=16)
                            ln = ln*100/65535
                            feedback = {
                                self.tp: "lightnessStatus",
                                self.pl: {
                                    "address": tmps[self.pl]["a"],
                                    "value": round(ln)
                                }
                            }
                            return json.dumps(feedback)

                        elif (topic == "iv_reponst"):
                            payload = tmps[self.pl]

                            iv_Index = payload["indexIV"]
                            f = open(url_config_db, "r")
                            data_f = json.loads(f.read())
                            f.close()

                            data_f["indexIV"] = iv_Index
                            f = open(url_config_db, "w")
                            f.write(json.dumps(data_f, indent=4))
                            f.close()

                            # return json.dumps(tmps)

                        elif (topic == "delete_node"):
                            # log.debug("delete_node")
                            payload = tmps[self.pl]

                            dat = {"address": payload["unicast"]}
                            self.request("devkey_delete", json.dumps(dat))
                            time.sleep(0.2)
                            self.request(
                                "addr_publication_remove", json.dumps(dat))
                            return json.dumps(tmps)

                        elif (topic == "config_subscribe_model_add"):
                            # log.debug("config_subscribe_model_add")
                            if self.handle == "config_subscribe_model_delete":
                                payload = tmps[self.pl]

                                try:
                                    f = open(url_sigMesh_db, "r")
                                    data_sigMesh = json.loads(f.read())
                                    f.close()
                                    models_sub = []
                                    for node in data_sigMesh["nodes"]:
                                        if node["unicastAddress"] == payload["element address"]:
                                            # log.debug(node)
                                            for model in node["elements"][0]["models"]:
                                                if model["modelId"] == payload["model identifier"]:
                                                    index_node = list(
                                                        data_sigMesh["nodes"]).index(node)

                                                    index_model = list(
                                                        data_sigMesh["nodes"][index_node]["elements"][0]["models"]).index(model)
                                                    models_sub = list(
                                                        model["subscribe"]).copy()
                                                    models_sub.remove(
                                                        payload["addr"])
                                                    data_sigMesh["nodes"][index_node]["elements"][0][
                                                        "models"][index_model]["subscribe"] = models_sub
                                                    break
                                    f = open(url_sigMesh_db, "w")
                                    f.write(json.dumps(
                                        data_sigMesh, indent=4))
                                    f.close()
                                except:
                                    pass
                                # log.debug(tmps)
                                if (len(self.models_device_sub_remove) > 0):
                                    dat = {
                                        "unicast": self.models_device_sub_remove_unicast,
                                        "elementAddress": self.models_device_sub_remove_unicast,
                                        "modelIdentifier": self.models_device_sub_remove[0],
                                        "subscribeAddress": self.models_device_sub_remove_address_group
                                    }
                                    self.request("config_subscribe_model_delete",
                                                 json.dumps(dat), NUMBER_REPEAT, TIME_REPEAT)
                                    del self.models_device_sub_remove[0]
                                else:
                                    # log.debug("remove thanh công")
                                    self.res_error = {
                                        self.tp: "remove_group", self.pl: {"status": "00"}}
                                    self.status_fb = True
                                    if self.tpRepeat == "config_subscribe_model_delete":
                                        self.tpRepeat = None
                                    # self.res_error[self.tp] = 'remove_group'
                                    # self.res_error[self.pl]["status"] = "00"
                                    # self.status_fb = True
                                # return json.dumps(tmps)
                                if payload["status"] != "00":
                                    if (len(self.models_device_sub_remove) > 0):
                                        dat = {
                                            "unicast": self.models_device_sub_remove_unicast,
                                            "elementAddress": self.models_device_sub_remove_unicast,
                                            "modelIdentifier": self.models_device_sub_remove[0],
                                            "subscribeAddress": self.models_device_sub_remove_address_group
                                        }
                                        self.request("config_subscribe_model_delete",
                                                     json.dumps(dat), NUMBER_REPEAT, TIME_REPEAT)
                                        del self.models_device_sub_remove[0]

                            elif self.handle == "config_subscribe_model_add":
                                payload = tmps[self.pl]
                                # log.debug(tmps)

                                f = open(url_sigMesh_db, "r")
                                data_sigMesh = json.loads(f.read())
                                f.close()
                                models_sub = []
                                for node in data_sigMesh["nodes"]:
                                    if node["unicastAddress"] == payload["element address"]:
                                        # log.debug(node)
                                        for model in node["elements"][0]["models"]:
                                            if model["modelId"] == payload["model identifier"]:
                                                index_node = list(
                                                    data_sigMesh["nodes"]).index(node)

                                                index_model = list(
                                                    data_sigMesh["nodes"][index_node]["elements"][0]["models"]).index(model)
                                                models_sub = list(
                                                    model["subscribe"]).copy()
                                                x = payload["addr"] in models_sub
                                                if not x:
                                                    models_sub.append(
                                                        payload["addr"])
                                                    data_sigMesh["nodes"][index_node]["elements"][0][
                                                        "models"][index_model]["subscribe"] = models_sub
                                                break

                                f = open(url_sigMesh_db, "w")
                                f.write(json.dumps(
                                    data_sigMesh, indent=4))
                                f.close()
                                # log.debug(tmps)
                                if (len(self.models_device_sub) > 0):
                                    dat = {
                                        "unicast": self.models_device_sub_unicast,
                                        "elementAddress": self.models_device_sub_unicast,
                                        "modelIdentifier": self.models_device_sub[0],
                                        "subscribeAddress": self.models_device_sub_address_group
                                    }
                                    time.sleep(0.2)
                                    self.request("config_subscribe_model_add",
                                                 json.dumps(dat), NUMBER_REPEAT, TIME_REPEAT)
                                    del self.models_device_sub[0]
                                else:
                                    # self.res_error[self.tp] = 'add_group'
                                    # self.res_error[self.pl]["status"] = "00"
                                    # log.debug("add thanh công")
                                    self.res_error = {
                                        self.tp: "add_group", self.pl: {"status": "00"}}
                                    self.status_fb = True
                                    if self.tpRepeat == "config_subscribe_model_add":
                                        self.tpRepeat = None

                                if payload["status"] != "00":
                                    if (len(self.models_device_sub) > 0):
                                        dat = {
                                            "unicast": self.models_device_sub_unicast,
                                            "elementAddress": self.models_device_sub_unicast,
                                            "modelIdentifier": self.models_device_sub[0],
                                            "subscribeAddress": self.models_device_sub_address_group
                                        }
                                        time.sleep(0.2)
                                        self.request("config_subscribe_model_add",
                                                     json.dumps(dat), NUMBER_REPEAT, TIME_REPEAT)
                                        del self.models_device_sub[0]
                                    return json.dumps(tmps)

                        elif (topic == "red_iv"):
                            pass
                        else:

                            return json.dumps(tmps)
                    except:
                        log.error("error part json reponse: %s",
                                  json.dumps(tmps))
