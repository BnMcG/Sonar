import bluetooth
import bluetooth._bluetooth as bt
import struct
import array
import fcntl
import os
from yaml import load as load_yaml, FullLoader
import paho.mqtt.client as mqtt
import time
import sys
import json
import datetime


class BluetoothRSSI(object):
    """Object class for getting the RSSI value of a Bluetooth address."""

    def __init__(self, addr):
        self.addr = addr
        self.hci_sock = bt.hci_open_dev()
        self.hci_fd = self.hci_sock.fileno()
        self.bt_sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
        self.bt_sock.settimeout(10)
        self.connected = False
        self.cmd_pkt = None

    def prep_cmd_pkt(self):
        """Prepare the command packet for requesting RSSI."""
        reqstr = struct.pack(
            b'6sB17s', bt.str2ba(self.addr), bt.ACL_LINK, b'\0' * 17)
        request = array.array('b', reqstr)
        handle = fcntl.ioctl(self.hci_fd, bt.HCIGETCONNINFO, request, 1)
        handle = struct.unpack(b'8xH14x', request.tostring())[0]
        self.cmd_pkt = struct.pack('H', handle)

    def connect(self):
        """Connect to the Bluetooth device."""
        # Connecting via PSM 1 - Service Discovery
        self.bt_sock.connect_ex((self.addr, 1))
        self.connected = True

    def request_rssi(self):
        """Request the current RSSI value.
        @return: The RSSI value or None if the device connection fails
                 (i.e. the device is not in range).
        """
        try:
            # Only do connection if not already connected
            if not self.connected:
                self.connect()
            # Command packet prepared each iteration to allow disconnect to trigger IOError
            self.prep_cmd_pkt()
            # Send command to request RSSI
            rssi = bt.hci_send_req(
                self.hci_sock, bt.OGF_STATUS_PARAM,
                bt.OCF_READ_RSSI, bt.EVT_CMD_COMPLETE, 4, self.cmd_pkt)
            rssi = struct.unpack('b', rssi[3].to_bytes(1, 'big'))
            return rssi
        except IOError as e:
            print(e)
            # Happens if connection fails (e.g. device is not in range)
            self.connected = False
            # Socket recreated to allow device to successfully reconnect
            self.bt_sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
            return None


def listen():
    # Load configuration
    script_directory = os.path.dirname(os.path.realpath(__file__))
    config_file_path = os.path.join(script_directory, '../', 'sonar.yaml')

    with open(config_file_path, 'r') as config_file:
        config = load_yaml(config_file, Loader=FullLoader)

    # Configure MQTT client
    mqtt_client = mqtt.Client(clean_session=True)

    if config['mqtt']['tls']:
        print("Setting TLS...")
        mqtt_client.tls_set()

    if config['mqtt']['username'] and config['mqtt']['password']:
        print("Setting authentication parameters...")
        mqtt_client.username_pw_set(config['mqtt']['username'], config['mqtt']['password'])

    mqtt_client.connect(host=config['mqtt']['host'], port=config['mqtt']['port'])
    mqtt_client.loop_start()

    while True:
        try:
            for device_address in config['devices']:
                device_query = BluetoothRSSI(device_address)
                rssi_data = device_query.request_rssi()
                print(rssi_data)

                if rssi_data is None:
                    rssi = -999
                else:
                    rssi = rssi_data[0]

                payload = {
                    'timestamp': datetime.datetime.now().timestamp(),
                    'rssi': rssi,  # Nonsensical value if device not found
                    'device': device_address,
                    'sonar': config['sonar']['name']
                }

                mqtt_client.publish(
                    topic=config['mqtt']['topic'],
                    payload=json.dumps(payload))

            time.sleep(config['sonar']['interval'])
        except KeyboardInterrupt:
            mqtt_client.loop_stop()
            sys.exit()


if __name__ == '__main__':
    listen()
