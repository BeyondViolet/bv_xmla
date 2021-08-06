'''
Created on 18.04.2012

@author: norman
'''
import httpx

from .interfaces import XMLAException
from zeep import Plugin, AsyncClient
from zeep.exceptions import Fault
from zeep.transports import AsyncTransport

#import types
from .formatreader import TupleFormatReader, TupleFormatReaderTabular
from .utils import *
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


schema_xmla="urn:schemas-microsoft-com:xml-analysis"
schema_xmla_rowset="urn:schemas-microsoft-com:xml-analysis:rowset"
schema_xmla_mddataset="urn:schemas-microsoft-com:xml-analysis:mddataset"
schema_soap_env="http://schemas.xmlsoap.org/soap/envelope/"
schema_xml="http://www.w3.org/2001/XMLSchema"

# the following along with changes to the wsdl (elementFormDefault="unqualified") is needed
# to make it fly with icCube, which expects elements w/o namespace prefix
class LogRequest(Plugin):
    def __init__(self, enabled=True):
        self.enabled = enabled

    def egress(self, envelope, http_headers, operation, binding_options):
        if self.enabled:
            print(etree_tostring(envelope))

    def ingress(self, envelope, http_headers, operation):
        if self.enabled:
            print(etree_tostring(envelope))

    def enable(self):
        self.enabled=True
    def disable(self):
        self.enabled=False

class SessionPlugin(Plugin):
  def __init__(self, xmlaconn):
      self.xmlaconn = xmlaconn

  def ingress(self, envelope, http_headers, operation):
    #print(etree_tostring(envelope))
    if self.xmlaconn.getListenOnSessionId():
        nsmap={'se': schema_soap_env,
               'xmla': schema_xmla}
        s=envelope.xpath("/se:Envelope/se:Header/xmla:Session", namespaces=nsmap)[0]
        sid=s.attrib.get("SessionId")
        self.xmlaconn.setSessionId(sid)


# lsit of XMLA1.1 rowsets: 
xmla1_1_rowsets = ["DISCOVER_DATASOURCES",
                   "DISCOVER_PROPERTIES", 
                   "DISCOVER_SCHEMA_ROWSETS",
                   "DISCOVER_ENUMERATORS",
                   "DISCOVER_LITERALS",
                   "DISCOVER_KEYWORDS",
                   "DBSCHEMA_CATALOGS",
                   "DBSCHEMA_COLUMNS",
                   "DBSCHEMA_TABLES",
                   "DBSCHEMA_TABLES_INFO",
                   "DBSCHEMA_PROVIDER_TYPES",
                   "MDSCHEMA_ACTIONS",
                   "MDSCHEMA_CUBES",
                   "MDSCHEMA_DIMENSIONS",
                   "MDSCHEMA_FUNCTIONS",
                   "MDSCHEMA_HIERARCHIES",
                   "MDSCHEMA_MEASURES",
                   "MDSCHEMA_MEMBERS",
                   "MDSCHEMA_PROPERTIES",
                   "MDSCHEMA_SETS"
                   ]

class XMLAConnection(object):
    
    @classmethod
    def addMethod(cls, funcname, func):
        return setattr(cls, funcname, func)

        
    @classmethod
    def setupMembers(cls):
        def getFunc(schemaName):
            return lambda this, *args, **kw: cls.Discover(this, 
                                                          schemaName, 
                                                          *args, **kw)
        
        for schemaName in xmla1_1_rowsets:
            mname = schemaNameToMethodName(schemaName)
            cls.addMethod( mname, getFunc(schemaName) )

    def __init__(self, url, sslverify, **kwargs):

        transport = AsyncTransport(verify_ssl=sslverify)

        if "username" in kwargs and "password" in kwargs:
            auth = (kwargs['username'], kwargs['password'])
        else:
            auth = None
        httpx_client = httpx.AsyncClient(auth=auth, verify=sslverify, http2=True)

        transport.client = httpx_client
        transport.wsdl_client =  httpx.Client(
            verify=sslverify,
            proxies=None,
            timeout=300,
            auth=auth
        )

        self.sessionplugin=SessionPlugin(self)
        plugins=[self.sessionplugin]

        if "log" in kwargs:
            log = kwargs.get("log")
            if isinstance(log, Plugin):
                plugins.append(log)
            elif log == True:
                plugins.append(LogRequest())
            del kwargs["log"]
            
        self.client = AsyncClient(url,
                             transport=transport, 
                             # cache=None, unwrap=False,
                             plugins=plugins)

        self.service = self.client.bind("MsXmlAnalysis", "MsXmlAnalysisSoap")
        self.client.set_ns_prefix(None, schema_xmla)
        # optional, call might fail
        self.getMDSchemaLevels = lambda *args, **kw: self.Discover("MDSCHEMA_LEVELS", 
                                                                   *args, **kw)
        self.setListenOnSessionId(False)
        self.setSessionId(None)
        self._soapheaders=None
             

    def getListenOnSessionId(self):
        return self.listenOnSessionId

    def setListenOnSessionId(self, trueOrFalse):
        self.listenOnSessionId = trueOrFalse

    def setSessionId(self, sessionId):
        self.sessionId = sessionId
        
    async def Discover(self, what, restrictions=None, properties=None):
        rl = as_etree(restrictions, "RestrictionList")
        pl = as_etree(properties, "PropertyList")
        try:
            #import pdb; pdb.set_trace()
            doc = await self.service.Discover(RequestType=what, Restrictions=rl, Properties=pl, _soapheaders=self._soapheaders)
            root = fromETree(doc.body["return"]["_value_1"], ns=schema_xmla_rowset)
            res = getattr(root, "row", [])
            if res:
                res = aslist(res)
        except Fault as fault:
            raise XMLAException(fault.message, dictify(fromETree(fault.detail, ns=None)))
        #logger.debug( res )
        return res


    async def Execute(self, command, dimformat="Multidimensional",
                axisFormat="TupleFormat", **kwargs):
        if isinstance(command, stringtypes):
            command=as_etree({"Statement": command})
        props = {"Format":dimformat, "AxisFormat":axisFormat}
        props.update(kwargs)

        plist = as_etree({"PropertyList":props})
        ns = schema_xmla_mddataset if dimformat == "Multidimensional" else schema_xmla_rowset
        reader = TupleFormatReader if dimformat == "Multidimensional" else TupleFormatReaderTabular
        try:
            
            res = await self.service.Execute(Command=command, Properties=plist, _soapheaders=self._soapheaders)
            root = res.body["return"]["_value_1"]
            cols = None if dimformat == "Multidimensional" else fromETree(root, ns=schema_xml, name="schema")
            rows = fromETree(root, ns=ns)
            return reader(rows, cols)
        except Fault as fault:
            raise XMLAException(fault.message, dictify(fromETree(fault.detail, ns=None)))
        
        
    async def BeginSession(self):
        bs= self.client.get_element(ns_name(schema_xmla,"BeginSession"))(mustUnderstand=1)
        self.setListenOnSessionId(True)
        cmd = as_etree("Statement")

        await self.service.Execute(Command=cmd,_soapheaders={"BeginSession":bs})
        self.setListenOnSessionId(False)

        sess= self.client.get_element(ns_name(schema_xmla,"Session"))(SessionId=self.sessionId, mustUnderstand = 1)
        self._soapheaders={"Session":sess}
        
    async def EndSession(self):
        if self.sessionId is not None:
            es= self.client.get_element(ns_name(schema_xmla,"EndSession"))(SessionId=self.sessionId, mustUnderstand = 1)
            cmd = as_etree("Statement")
            await self.service.Execute(Command=cmd, _soapheaders={"EndSession":es})
            self.setSessionId(None)
            self._soapheaders=None

    async def close(self):
        await self.client.transport.aclose()

                
XMLAConnection.setupMembers()
