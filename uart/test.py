from uart import UART
import json
import threading

import logging
import logging.config
logging.config.fileConfig(fname='../config/log.conf',
                          disable_existing_loggers=False)
log = logging.getLogger("test.py")


uart = UART('COM6', 115200)


def input_message():
    while True:
        ip = input()
        try:
            ip = json.loads(ip)
            topic = ip["topic"]
            payload = ip["payload"]
        except:
            pass
        # {"topic": "scan_device", "payload":{"status":true}}
        # {"topic": "scan_device", "payload":{"status":false}}
        if topic == "scan_device":
            status = payload["status"]
            uart.scan_device(status)

        # {"topic": "add_device", "payload":{"name":"light 2", "uuid":"422CFE8138D04717A9CC29FC6EA85215"}}
        elif topic == "add_device":
            name = payload["name"]
            uuid = payload["uuid"]
            uart.add_device(name, uuid)

        # {"topic": "onoff_device", "payload":{"unicastAddress":"000E", "status":true}}
        # {"topic": "onoff_device", "payload":{"unicastAddress":"0003", "status":false}}
        elif topic == "onoff_device":
            unicastAddress = payload["unicastAddress"]
            status = payload["status"]
            uart.onoff_device(unicastAddress, status)

        # {"topic": "onoff_group", "payload":{"unicastAddress":"C000", "status":true}}
        # {"topic": "onoff_group", "payload":{"unicastAddress":"C000", "status":false}}
        elif topic == "onoff_group":
            unicastAddress = payload["unicastAddress"]
            status = payload["status"]
            uart.onoff_group(unicastAddress, status)

        # {"topic": "delete_network", "payload":{}}
        elif topic == "delete_network":
            uart.delete_network()

        # {"topic": "lightness_device", "payload":{"unicast": "0003","value":50}}
        elif topic == "lightness_device":
            unicast = payload["unicast"]
            value = payload["value"]
            uart.lightness_device(unicast, value)

        # {"topic": "lightness_group", "payload":{"unicast": "C000","value":50}}
        elif topic == "lightness_group":
            unicast = payload["unicast"]
            value = payload["value"]
            uart.lightness_group(unicast, value)

        # {"topic": "delete_node", "payload":{"unicastAddress":"0003"}}
        elif topic == "delete_node":
            unicastAddress = payload["unicastAddress"]
            uart.delete_node(unicastAddress)

        # {"topic": "creat_group", "payload":{"name":"group1"}}
        elif topic == "creat_group":
            name = payload["name"]
            uart.creat_group(name)
        # {"topic": "add_group", "payload":{"addressDevice":"0004","addressGroup":"C000"}}
        elif topic == "add_group":
            addressDevice = payload["addressDevice"]
            addressGroup = payload["addressGroup"]
            uart.add_group(addressDevice, addressGroup)

        # {"topic": "remove_group", "payload":{"addressDevice":"0004","addressGroup":"C000"}}
        elif topic == "remove_group":
            addressDevice = payload["addressDevice"]
            addressGroup = payload["addressGroup"]
            uart.remove_group(addressDevice, addressGroup)
        # {"topic": "delete_group", "payload":{"addressGroup":"C000"}}
        elif topic == "delete_group":
            addressGroup = payload["addressGroup"]
            uart.delete_group(addressGroup)

        else:
            exit(0)


def listen_event():
    while True:
        data = uart.event()
        if data != None:
            log.debug(data)


thread_input = threading.Thread(target=input_message)
thread_input.start()
thread_event = threading.Thread(target=listen_event)
thread_event.start()


"""
    start scan
{"topic": "scan_device", "payload":{"status":true}}
    stop scan
{"topic": "scan_device", "payload":{"status":false}}

    thêm thiết bị
{"topic": "add_device", "payload":{"name":"light 2", "uuid":"018071902600008CAEB1514719020000"}}

    On đèn
{"topic": "onoff_device", "payload":{"unicastAddress":"0004", "status":true}}
    Off đèn
{"topic": "onoff_device", "payload":{"unicastAddress":"0003", "status":false}}

    On group
{"topic": "onoff_group", "payload":{"unicastAddress":"C000", "status":true}}
    Off group
{"topic": "onoff_group", "payload":{"unicastAddress":"C000", "status":false}}

    lightness đèn
{"topic": "lightness_device", "payload":{"unicast": "0003","value":50}}

    lightness_group
{"topic": "lightness_group", "payload":{"unicast": "C000","value":5}}

    Thêm group
{"topic": "creat_group", "payload":{"name":"group1"}}

    thêm thiết bị vào group
{"topic": "add_group", "payload":{"addressDevice":"0005","addressGroup":"C000"}}

    xóa thiết bị khỏi group
{"topic": "remove_group", "payload":{"addressDevice":"0003","addressGroup":"C000"}}

    Xóa group
{"topic": "delete_group", "payload":{"addressGroup":"C001"}}

    Xóa thiết bị
{"topic": "delete_node", "payload":{"unicastAddress":"0003"}}

    delete_network
{"topic": "delete_network", "payload":{}}
"""
