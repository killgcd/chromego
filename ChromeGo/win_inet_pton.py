# This software released into the public domain. Anyone is free to copy,
# modify, publish, use, compile, sell, or distribute this software,
# either in source code form or as a compiled binary, for any purpose,
# commercial or non-commercial, and by any means.

import os
import sys
import socket

PY2 = sys.version_info[0] == 2
PY3 = sys.version_info[0] == 3
PY35 = PY3 and sys.version_info[1] == 5

if PY3:
    # Add bytes input compatible
    inet_aton_o = socket.inet_aton

    def inet_aton(ip_string):
        if isinstance(ip_string, bytes):
            ip_string = ip_string.decode()
        return inet_aton_o(ip_string)

    socket.inet_aton = inet_aton

    if hasattr(socket, 'inet_pton'):
        inet_pton_o = socket.inet_pton

        def inet_pton(address_family, ip_string):
            if isinstance(ip_string, bytes):
                ip_string = ip_string.decode()
            return inet_pton_o(address_family, ip_string)

        socket.inet_pton = inet_pton

if not PY35:
    # Add bytearray input compatible
    inet_ntoa_o = socket.inet_ntoa

    def inet_ntoa(packed_ip):
        if isinstance(packed_ip, bytearray):
            return inet_ntoa_o(bytes(packed_ip))
        return inet_ntoa_o(packed_ip)

    socket.inet_ntoa = inet_ntoa

    if hasattr(socket, 'inet_ntop'):
        inet_ntop_o = socket.inet_ntop

        def inet_ntop(address_family, packed_ip):
            if isinstance(packed_ip, bytearray):
                return inet_ntop_o(address_family, bytes(packed_ip))
            return inet_ntop_o(address_family, packed_ip)

        socket.inet_ntop = inet_ntop

if not hasattr(socket, 'inet_pton') and os.name == 'nt':

    import ctypes

    class sockaddr(ctypes.Structure):
        _fields_ = [("sa_family", ctypes.c_short),
                    ("__pad1", ctypes.c_ushort),
                    ("ipv4_addr", ctypes.c_byte * 4),
                    ("ipv6_addr", ctypes.c_byte * 16),
                    ("__pad2", ctypes.c_ulong)]

    if hasattr(ctypes, 'windll'):
        WSAStringToAddressA = ctypes.windll.ws2_32.WSAStringToAddressA
        WSAAddressToStringA = ctypes.windll.ws2_32.WSAAddressToStringA
    else:
        def not_windows():
            raise SystemError(
                "Invalid platform. ctypes.windll must be available."
            )
        WSAStringToAddressA = not_windows
        WSAAddressToStringA = not_windows

    def inet_pton(address_family, ip_string):
        if PY2 and isinstance(ip_string, unicode):
            # Add unicode input compatible
            ip_string = ip_string.encode('ascii')

        addr = sockaddr()
        addr.sa_family = address_family
        addr_size = ctypes.c_int(ctypes.sizeof(addr))

        if WSAStringToAddressA(
                ip_string,
                address_family,
                None,
                ctypes.byref(addr),
                ctypes.byref(addr_size)
        ) != 0:
            raise ValueError(ctypes.FormatError())

        if address_family == socket.AF_INET:
            return ctypes.string_at(addr.ipv4_addr, 4)
        if address_family == socket.AF_INET6:
            return ctypes.string_at(addr.ipv6_addr, 16)

        raise ValueError('unknown address family')

    def inet_ntop(address_family, packed_ip):
        if isinstance(packed_ip, bytearray):
            # Add bytearray input compatible
            packed_ip = bytes(packed_ip)

        addr = sockaddr()
        addr.sa_family = address_family
        addr_size = ctypes.c_int(ctypes.sizeof(addr))
        ip_string = ctypes.create_string_buffer(128)
        ip_string_size = ctypes.c_int(ctypes.sizeof(ip_string))

        if address_family == socket.AF_INET:
            if len(packed_ip) != ctypes.sizeof(addr.ipv4_addr):
                raise ValueError('packed IP wrong length for inet_ntop')
            ctypes.memmove(addr.ipv4_addr, packed_ip, 4)
        elif address_family == socket.AF_INET6:
            if len(packed_ip) != ctypes.sizeof(addr.ipv6_addr):
                raise ValueError('packed IP wrong length for inet_ntop')
            ctypes.memmove(addr.ipv6_addr, packed_ip, 16)
        else:
            raise ValueError('unknown address family')

        if WSAAddressToStringA(
                ctypes.byref(addr),
                addr_size,
                None,
                ip_string,
                ctypes.byref(ip_string_size)
        ) != 0:
            raise ValueError(ctypes.FormatError())

        ip = ip_string[:ip_string_size.value - 1]
        return ip.decode() if hasattr(ip, 'fromhex') else ip

    # Adding our two functions to the socket library
    socket.inet_pton = inet_pton
    socket.inet_ntop = inet_ntop
