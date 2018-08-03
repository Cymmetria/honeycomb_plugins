
import re
import sys

from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.carrier.asynsock.dgram import udp
from pysnmp.proto.api import v2c

RE_FROM_HELL = r'^(?P<oid>[.](\d+[.])+(\d+)) = (?P<value>([^"{}]+$)|("((([^"])|((?<!\\)\\((\\\\)*)"))+)"$))'.format('\n')

def get_type(x):
    if isinstance(x, str):
        return v2c.OctetString()
    if isinstance(x, int):
        return v2c.Integer()

def convert_scalar(x):
    if x.startswith('"') and x.endswith('"'):
        return x[1:-1]
    if re.match(r'\d+$', x):
        return int(x)
    return x

def parse_oid(oid_str):
    oid_str = oid_str.strip('.')
    return tuple([int(x) for x in oid_str.strip().split('.')])


def load_mib(filename):
    with open(filename, 'rb') as f:
        text = f.read()
    db = [x.groupdict() for x in re.finditer(RE_FROM_HELL, text, re.MULTILINE)]
    return {parse_oid(x['oid']): convert_scalar(x['value']) for x in db}

def main(mib_filename):
    snmp_engine = engine.SnmpEngine()
    config.addSocketTransport(
        snmp_engine,
        udp.domainName,
        udp.UdpTransport().openServerMode(('0.0.0.0', 161))
    )
    config.addV1System(snmp_engine, 'my-area', 'public')

    config.addVacmUser(snmp_engine, 2, 'my-area', 'noAuthNoPriv', (1,))

    snmp_context = context.SnmpContext(snmp_engine)
    mib_builder = snmp_context.getMibInstrum().getMibBuilder()
    MibScalar, MibScalarInstance = mib_builder.importSymbols(
        'SNMPv2-SMI', 'MibScalar', 'MibScalarInstance'
    )

    mib_db = load_mib(mib_filename)

    class MyStaticMibScalarInstance(MibScalarInstance):
        def getValue(self, name, idx):
            print 'FUCK FUCK', name, 'BLABLA', idx
            if name in mib_db:
                return self.getSyntax().clone(
                    mib_db[name]
                )
            if name[:-1] in mib_db:
                return self.getSyntax().clone(
                    mib_db[name[:-1]]
                )

    params = [MibScalar(key, get_type(value)) for key, value in mib_db.items()]
    params += [MyStaticMibScalarInstance(key, (0,), get_type(value)) for key, value in mib_db.items()]

    #mib_builder.exportSymbols(
      #'__MY_MIB', MibScalar((1,3,6,5,1), v2c.OctetString()),
      #            MyStaticMibScalarInstance((1,3,6,5,1), (0,), v2c.OctetString())
    #)
    mib_builder.exportSymbols('__MY_MIB', *params)

    cmdrsp.GetCommandResponder(snmp_engine, snmp_context)
    cmdrsp.NextCommandResponder(snmp_engine, snmp_context)
    cmdrsp.BulkCommandResponder(snmp_engine, snmp_context)

    # Register an imaginary never-ending job to keep I/O dispatcher running forever
    snmp_engine.transportDispatcher.jobStarted(1)

    # Run I/O dispatcher which would receive queries and send responses
    try:
        snmp_engine.transportDispatcher.runDispatcher()
    except:
        snmp_engine.transportDispatcher.closeDispatcher()
        raise

if __name__ == '__main__':
    main(sys.argv[1])
