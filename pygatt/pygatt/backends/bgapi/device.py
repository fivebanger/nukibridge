import logging
import time

# for Python 2/3 compatibility
try:
    import queue
except ImportError:
    import Queue as queue

import threading

from pygatt import BLEDevice, exceptions
from . import bglib, constants
from .bgapi import BGAPIError
from .error_codes import ErrorCode
from .packets import BGAPICommandPacketBuilder as CommandBuilder
from .bglib import EventPacketType, ResponsePacketType

log = logging.getLogger(__name__)


def connection_required(func):
    """Raise an exception if the device is not connected before calling the
    actual function.
    """
    def wrapper(self, *args, **kwargs):
        if self._handle is None:
            raise exceptions.NotConnectedError()
        return func(self, *args, **kwargs)
    return wrapper


class BGAPIBLEDevice(BLEDevice):
    def __init__(self, address, handle, backend):
        super(BGAPIBLEDevice, self).__init__(address)
        self._handle = handle
        self._backend = backend

    @connection_required
    def bond(self, permanent=False):
        """
        Create a bond and encrypted connection with the device.
        """

        # Set to bondable mode so bonds are store permanently
        if permanent:
            self._backend.set_bondable(True)
        log.debug("Bonding to %s", self._address)
        self._backend.send_command(
            CommandBuilder.sm_encrypt_start(
                self._handle, constants.bonding['create_bonding']))
        self._backend.expect(ResponsePacketType.sm_encrypt_start)

        packet_type, response = self._backend.expect_any(
            [EventPacketType.connection_status,
             EventPacketType.sm_bonding_fail])
        if packet_type == EventPacketType.sm_bonding_fail:
            raise BGAPIError("Bonding failed")
        log.info("Bonded to %s", self._address)

    @connection_required
    def get_rssi(self):
        """
        Get the receiver signal strength indicator (RSSI) value from the device.

        Returns the RSSI as in integer in dBm.
        """
        # The BGAPI has some strange behavior where it will return 25 for
        # the RSSI value sometimes... Try a maximum of 3 times.
        for i in range(0, 3):
            self._backend.send_command(
                CommandBuilder.connection_get_rssi(self._handle))
            _, response = self._backend.expect(
                ResponsePacketType.connection_get_rssi)
            rssi = response['rssi']
            if rssi != 25:
                return rssi
            time.sleep(0.1)
        raise BGAPIError("get rssi failed")

    @connection_required
    def char_read(self, uuid, timeout=None):
        return self.char_read_handle(self.get_handle(uuid), timeout=timeout)

    @connection_required
    def char_read_handle(self, handle, timeout=None):
        log.info("Reading characteristic at handle %d", handle)
        self._backend.send_command(
            CommandBuilder.attclient_read_by_handle(
                self._handle, handle))

        self._backend.expect(ResponsePacketType.attclient_read_by_handle)
        success = False
        while not success:
            matched_packet_type, response = self._backend.expect_any(
                [EventPacketType.attclient_attribute_value,
                 EventPacketType.attclient_procedure_completed],
                timeout=timeout)
            # TODO why not just expect *only* the attribute value response,
            # then it would time out and raise an exception if allwe got was
            # the 'procedure completed' response?
            if matched_packet_type != EventPacketType.attclient_attribute_value:
                raise BGAPIError("Unable to read characteristic")
            if response['atthandle'] == handle:
                # Otherwise we received a response from a wrong handle (e.g.
                # from a notification) so we keep trying to wait for the
                # correct one
                success = True
        return bytearray(response['value'])

    @connection_required
    def char_write_handle(self, char_handle, value, wait_for_response=False):

        while True:
            value_list = [b for b in value]
            if wait_for_response:
                self._backend.send_command(
                    CommandBuilder.attclient_attribute_write(
                        self._handle, char_handle, value_list))
                self._backend.expect(
                    ResponsePacketType.attclient_attribute_write)
                packet_type, response = self._backend.expect(
                    EventPacketType.attclient_procedure_completed)
            else:
                self._backend.send_command(
                    CommandBuilder.attclient_write_command(
                        self._handle, char_handle, value_list))
                packet_type, response = self._backend.expect(
                    ResponsePacketType.attclient_write_command)

            if (response['result'] !=
                    ErrorCode.insufficient_authentication.value):
                # Continue to retry until we are bonded
                break

    @connection_required
    def char_write_handle_long(self, char_handle, value, chunk_size=20, wait_for_response=False):
        # TODO: handle wait_for_response
        offset = 0
        
        value_list = [b for b in value]
        length = len(value_list)
        
        while True:
            if( length < chunk_size ):
                chunk_size = length
            
            end = offset + chunk_size
            self._backend.send_command(
                CommandBuilder.attclient_prepare_write(
                    self._handle, char_handle, offset, value_list[offset:end]))
            
            self._backend.expect(ResponsePacketType.attclient_prepare_write)
            packet_type, response = self._backend.expect(
                EventPacketType.attclient_procedure_completed)

            length = length - chunk_size
            offset = end
            
            if( 0 == length ):
                break
            
        self._backend.send_command(
            CommandBuilder.attclient_execute_write(
                self._handle, 0x01))
        self._backend.expect(ResponsePacketType.attclient_execute_write)
        packet_type, response = self._backend.expect(
            EventPacketType.attclient_procedure_completed)

    @connection_required
    def char_write_handle_long_(self, char_handle, value, chunk_size=18, wait_for_response=False):
        # TODO: handle wait_for_response
        offset = 0
        
        value_list = [b for b in value]
        length = len(value_list)
        
        while True:
            if( length < chunk_size ):
                chunk_size = length
            
            end = offset + chunk_size
            self._backend.send_command(
                CommandBuilder.attclient_attribute_write(
                    self._handle, char_handle, value_list[offset:end]))
            self._backend.expect(
                ResponsePacketType.attclient_attribute_write)
            packet_type, response = self._backend.expect(
                EventPacketType.attclient_procedure_completed)

            length = length - chunk_size
            offset = end
            
            if( 0 == length ):
                break

    @connection_required
    def disconnect(self):
        log.debug("Disconnecting from %s", self._address)
        self._backend.send_command(
            CommandBuilder.connection_disconnect(self._handle))

        self._backend.expect(ResponsePacketType.connection_disconnect)
        log.info("Disconnected from %s", self._address)
        self._handle = None

    @connection_required
    def discover_characteristics(self):
        self._characteristics = self._backend.discover_characteristics(
            self._handle)
        return self._characteristics


class BGAPIBLEPeripheral(object):
    def __init__(self, backend):
        #super(BGAPIBLEDevice, self).__init__(address)
        self._backend = backend
        self._handles = []
        
        self._receiver = None
        self._running = None
        self._lock = threading.Lock()
        self._lib = bglib.BGLib()
        self._resp_pending = False

        # buffer for packets received
        self._receiver_queue = queue.Queue()

    def start(self):
        if self._running and self._running.is_set():
            self.stop()
        
        log.info('Start peripheral')

        self._receiver = threading.Thread(target=self._service)
        self._receiver.daemon = True

        self._running = threading.Event()
        self._running.set()
        self._receiver.start()

    def stop(self):
        if self._running:
            if self._running.is_set():
                log.info('Stop peripheral')
            self._running.clear()

        if self._receiver:
            self._receiver.join()
        self._receiver = None

    def disconnect(self, connection_handle):
        log.debug("Disconnecting from %s", connection_handle)
        self._backend.send_command(
            CommandBuilder.connection_disconnect(connection_handle))

        self._backend.expect(ResponsePacketType.connection_disconnect)
        log.info("Disconnected from %s", connection_handle)

    def _service(self):
        log.info("Running peripheral service")
        
        while self._running.is_set():
            if False == self._receiver_queue.empty():
                packet = self._receiver_queue.get()
                self._handle_packet(packet)
            time.sleep(0.01)
            pass

    def _handle_packet(self, packet):
        packet_type, args = self._lib.decode_packet(packet)
        
        if packet_type == EventPacketType.attributes_value:
            # hmk TODO: use const enum expression
            if 0x02 == args['reason']:
                connection = args['connection_handle']
                handle     = args['handle']
                offset     = args['offset']
                value_data = bytearray(args['value'])
                self._on_attributes_value(connection, handle, offset, value_data)
        elif packet_type == EventPacketType.attributes_user_read_request:
            connection = args['connection_handle']
            handle     = args['handle']
            offset     = args['offset']
            maxsize    = args['maxsize']
            self._on_attributes_user_read_request(connection, handle, offset, maxsize)
                

    def register_handle(self, handle, handle_cb):
        for item in self._handles:
            if item['handle'] == handle:
                # handle is already registered, return
                return
        self._handles.append({'handle': handle, 'handle_cb': handle_cb})


    def unregister_handle(self, handle):
        for i in range(0, len(self._handles)):
            if self._handles[i]['handle'] == handle:
                del self._handles[i]
                break


#============================================================================================
#                  !!!!!!! code is not verified yet !!!!!!!!!!!
#
#     def char_read_handle(self, handle, timeout=None, offset=0):
#         log.info("Reading characteristic from local GATT server at handle %d", handle)
#         self._backend.send_command(
#             CommandBuilder.attributes_read(
#                 handle, offset))
#  
#         self._backend.expect(ResponsePacketType.attributes_read)
#         success = False
#         while not success:
#             matched_packet_type, response = self._backend.expect_any(
#                 [EventPacketType.attclient_attribute_value,
#                  EventPacketType.attclient_procedure_completed],
#                 timeout=timeout)
#             # TODO why not just expect *only* the attribute value response,
#             # then it would time out and raise an exception if allwe got was
#             # the 'procedure completed' response?
#             if matched_packet_type != EventPacketType.attclient_attribute_value:
#                 raise BGAPIError("Unable to read characteristic")
#             if response['atthandle'] == handle:
#                 # Otherwise we received a response from a wrong handle (e.g.
#                 # from a notification) so we keep trying to wait for the
#                 # correct one
#                 success = True
#         return bytearray(response['value'])

    def char_write_handle_long(self, char_handle, value, chunk_size=20, wait_for_response=False):
        self._resp_pending = True
        wr_offset  = 0
        offset     = 0
        
        value_list = [b for b in value]
        length = len(value_list)
        
        while True:
            if( length < chunk_size ):
                chunk_size = length
            
            end = wr_offset + chunk_size
            self._backend.send_command(
                CommandBuilder.attributes_write(
                    char_handle, offset, value_list[wr_offset:end]))
            self._backend.expect(
                ResponsePacketType.attributes_write)

            if wait_for_response:
                packet_type, response = self._backend.expect(
                    EventPacketType.attclient_indicated)
                if (response['attrhandle'] != char_handle):
                    # TODO: do we need an error handler?
                    pass

            length    = length - chunk_size
            wr_offset = end
            
            if( 0 == length ):
                break
        self._resp_pending = False

    def char_write_handle(self, char_handle, value, wait_for_response=False, offset=0):
        log.info("Writing characteristic to local GATT server at handle %d", char_handle)
        self._resp_pending = True
        self._backend.send_command(
            CommandBuilder.attributes_write(
                char_handle, offset, value))
        self._backend.expect(
            ResponsePacketType.attributes_write)

        if wait_for_response:
            packet_type, response = self._backend.expect(
                EventPacketType.attclient_indicated)
            if (response['attrhandle'] != char_handle):
                # TODO: do we need an error handler?
                pass
        self._resp_pending = False

    def _on_attributes_value(self, connection, handle, offset, value):
        self._resp_pending = True
        self._backend.send_command(
            CommandBuilder.attributes_user_write_response(
                connection, 0x00))
        self._backend.expect(ResponsePacketType.attributes_user_write_response)
  
        for char_handle in self._handles:
            if handle == char_handle['handle']:
                if None != char_handle['handle_cb']:
                    char_handle['handle_cb'](connection, offset, value)
                break
        self._resp_pending = False

    def _on_attributes_user_read_request(self, connection, handle, offset, maxsize):
        self._resp_pending = True
        att_error = 0xFF
        value     = []
        read_cb   = None
        end       = True

        for char_handle in self._handles:
            if handle == char_handle['handle']:
                read_cb = char_handle['handle_cb']
                att_error = 0x00
                break
        
        while True:
            if None != read_cb:
                value, end = read_cb(connection, offset, maxsize)
                        
            self._backend.send_command(
                CommandBuilder.attributes_user_read_response(
                    connection, att_error, value))
            self._backend.expect(
                ResponsePacketType.attributes_user_read_response)
            
            # continue until end of data is sent, otherwise break.
            if True == end:
                break
        self._resp_pending = False

    def notify_read(self, packet):
        self._receiver_queue.put(packet)

    def notify_write(self, packet):
        self._receiver_queue.put(packet)

