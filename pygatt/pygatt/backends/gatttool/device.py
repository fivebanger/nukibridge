import functools
import logging

from pygatt import BLEDevice, exceptions

log = logging.getLogger(__name__)


def connection_required(func):
    """Raise an exception before calling the actual function if the device is
    not connection.
    """
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        if not self._connected:
            raise exceptions.NotConnectedError()
        return func(self, *args, **kwargs)
    return wrapper


class GATTToolBLEDevice(BLEDevice):
    """A BLE device connection initiated by the GATTToolBackend.

    Since the GATTToolBackend can only support 1 device connection at at time,
    the device implementation defers to the backend for all functionality -
    every command has to synchronize around a the same interactive gatttool
    session, using the same connection.
    """
    def __init__(self, address, backend):
        super(GATTToolBLEDevice, self).__init__(address)
        self._backend = backend
        self._connected = True

    @connection_required
    def bond(self, *args, **kwargs):
        self._backend.bond(self, *args, **kwargs)

    @connection_required
    def char_read(self, uuid, *args, **kwargs):
        return self._backend.char_read(self, uuid, *args, **kwargs)

    @connection_required
    def char_read_handle(self, handle, *args, **kwargs):
        return self._backend.char_read_handle(self, handle, *args, **kwargs)

    @connection_required
    def char_write_handle(self, handle, *args, **kwargs):
        self._backend.char_write_handle(self, handle, *args, **kwargs)

    @connection_required
    def char_write_handle_long(self, handle, value, chunk_size=20, wait_for_response=False):
        offset = 0
        
        value_list = [b for b in value]
        length = len(value_list)
        
        while True:
            if( length < chunk_size ):
                chunk_size = length
            
            end = offset + chunk_size
            
            self.char_write_handle(handle, value_list[offset:end], wait_for_response)

            length = length - chunk_size
            offset = end
            
            if( 0 == length ):
                break

    @connection_required
    def disconnect(self):
        self._backend.disconnect(self)
        self._connected = False

    @connection_required
    def discover_characteristics(self, *args, **kwargs):
        self._characteristics = self._backend.discover_characteristics(
            self, *args, **kwargs)
        return self._characteristics
