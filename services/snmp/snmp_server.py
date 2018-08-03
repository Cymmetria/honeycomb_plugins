# -*- coding: utf-8 -*-
"""SNMP honeypot - the actual implementation."""
from __future__ import unicode_literals


import pysnmp
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.carrier.asynsock.dgram import udp
from pysnmp.smi import instrum, error
from pysnmp.proto.api import v2c

class SNMPServer(object):
    def serve(self):
        engine = pysnmp.entity.engine.SnmpEngine()
        config.addSocketTranspot(
            engine,
            udp.domainName,
            udp.UdpTransport().openServerMode("0.0.0.0", 1161))
        config.addV1System(engine, 'my-area', 'public', contextName='my-context')

        snmp_context = context.SnmpContext(snmpEngine)
        cmdrsp.GetCommandResponder(snmp_engine, snmp_context)
        cmdrsp.SetCommandResponder(snmp_engine, snmp_context)
        snmp_engine.transportDispatcher.jobStarted(1)

        try:
            snmp_engine.transportDispatcher.runDispatcher()
        except Exception:
            snmp_engine.transportDispatcher.closeDispatcher()
            raise



def main():
    s = SNMPServer()



if __name__ == '__main__':
    main()
