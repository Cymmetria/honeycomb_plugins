<?xml version="1.0" encoding="utf-8"?>
<definitions xmlns:http="http://schemas.xmlsoap.org/wsdl/http/" xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsd1="http://tempuri.org/" xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/" xmlns:mime="http://schemas.xmlsoap.org/wsdl/mime/" targetNamespace="http://tempuri.org/" xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/" xmlns:s1="http://tempuri.org/AbstractTypes">
  <types>
    <xsd:schema elementFormDefault="qualified" targetNamespace="http://tempuri.org/">
      <xsd:element name="ProcessBase64Request">
        <xsd:complexType>
          <xsd:sequence>
            <xsd:element minOccurs="0" maxOccurs="1" name="bData" type="xsd1:ArrayOfByte" />
          </xsd:sequence>
        </xsd:complexType>
      </xsd:element>
      <xsd:element name="ProcessBase64RequestResponse">
        <xsd:complexType>
          <xsd:sequence>
            <xsd:element minOccurs="0" maxOccurs="1" name="ProcessBase64RequestResult" type="xsd1:ArrayOfByte" />
          </xsd:sequence>
        </xsd:complexType>
      </xsd:element>
      <xsd:element name="ProcessDimeRequest">
        <xsd:complexType />
      </xsd:element>
      <xsd:element name="ProcessDimeRequestResponse">
        <xsd:complexType>
          <xsd:sequence>
            <xsd:element minOccurs="1" maxOccurs="1" name="ProcessDimeRequestResult" type="xsd1:Void" />
          </xsd:sequence>
        </xsd:complexType>
      </xsd:element>
      <xsd:element name="ProcessDimeTestRequest">
        <xsd:complexType />
      </xsd:element>
      <xsd:element name="ProcessDimeTestRequestResponse">
        <xsd:complexType>
          <xsd:sequence>
            <xsd:element minOccurs="1" maxOccurs="1" name="ProcessDimeTestRequestResult" type="xsd1:Void" />
          </xsd:sequence>
        </xsd:complexType>
      </xsd:element>
      <xsd:element name="SayHelloTo">
        <xsd:complexType>
          <xsd:sequence>
            <xsd:element minOccurs="0" maxOccurs="1" name="name" type="xsd:string" />
          </xsd:sequence>
        </xsd:complexType>
      </xsd:element>
      <xsd:element name="SayHelloToResponse">
        <xsd:complexType>
          <xsd:sequence>
            <xsd:element minOccurs="0" maxOccurs="1" name="SayHelloToResult" type="xsd:string" />
          </xsd:sequence>
        </xsd:complexType>
      </xsd:element>
      <xsd:complexType name="Void" />
      <xsd:complexType name="ArrayOfByte">
        <xsd:sequence>
          <xsd:element minOccurs="0" maxOccurs="unbounded" name="Byte" type="xsd1:Byte" />
        </xsd:sequence>
      </xsd:complexType>
    </xsd:schema>
  </types>
  <message name="ProcessBase64RequestSoapIn">
    <part name="parameters" element="xsd1:ProcessBase64Request" />
  </message>
  <message name="ProcessBase64RequestSoapOut">
    <part name="parameters" element="xsd1:ProcessBase64RequestResponse" />
  </message>
  <message name="ProcessDimeRequestSoapIn">
    <part name="parameters" element="xsd1:ProcessDimeRequest" />
  </message>
  <message name="ProcessDimeRequestSoapOut">
    <part name="parameters" element="xsd1:ProcessDimeRequestResponse" />
  </message>
  <message name="ProcessDimeTestRequestSoapIn">
    <part name="parameters" element="xsd1:ProcessDimeTestRequest" />
  </message>
  <message name="ProcessDimeTestRequestSoapOut">
    <part name="parameters" element="xsd1:ProcessDimeTestRequestResponse" />
  </message>
  <message name="SayHelloToSoapIn">
    <part name="parameters" element="xsd1:SayHelloTo" />
  </message>
  <message name="SayHelloToSoapOut">
    <part name="parameters" element="xsd1:SayHelloToResponse" />
  </message>
  <message name="ProcessBase64RequestHttpGetIn">
    <part name="bData" type="xsd1:ArrayOfByte" />
  </message>
  <message name="ProcessBase64RequestHttpGetOut">
    <part name="Body" element="xsd1:ArrayOfByte" />
  </message>
  <message name="ProcessDimeRequestHttpGetIn" />
  <message name="ProcessDimeRequestHttpGetOut">
    <part name="Body" element="xsd1:Void" />
  </message>
  <message name="ProcessDimeTestRequestHttpGetIn" />
  <message name="ProcessDimeTestRequestHttpGetOut">
    <part name="Body" element="xsd1:Void" />
  </message>
  <message name="SayHelloToHttpGetIn">
    <part name="name" type="xsd:string" />
  </message>
  <message name="SayHelloToHttpGetOut">
    <part name="Body" element="xsd:string" />
  </message>
  <message name="ProcessBase64RequestHttpPostIn">
    <part name="bData" type="xsd1:ArrayOfByte" />
  </message>
  <message name="ProcessBase64RequestHttpPostOut">
    <part name="Body" element="xsd1:ArrayOfByte" />
  </message>
  <message name="ProcessDimeRequestHttpPostIn" />
  <message name="ProcessDimeRequestHttpPostOut">
    <part name="Body" element="xsd1:Void" />
  </message>
  <message name="ProcessDimeTestRequestHttpPostIn" />
  <message name="ProcessDimeTestRequestHttpPostOut">
    <part name="Body" element="xsd1:Void" />
  </message>
  <message name="SayHelloToHttpPostIn">
    <part name="name" type="xsd:string" />
  </message>
  <message name="SayHelloToHttpPostOut">
    <part name="Body" element="xsd:string" />
  </message>
  <portType name="EGatewaySoap">
    <operation name="ProcessBase64Request">
      <input message="xsd1:ProcessBase64RequestSoapIn" />
      <output message="xsd1:ProcessBase64RequestSoapOut" />
    </operation>
    <operation name="ProcessDimeRequest">
      <input message="xsd1:ProcessDimeRequestSoapIn" />
      <output message="xsd1:ProcessDimeRequestSoapOut" />
    </operation>
    <operation name="ProcessDimeTestRequest">
      <input message="xsd1:ProcessDimeTestRequestSoapIn" />
      <output message="xsd1:ProcessDimeTestRequestSoapOut" />
    </operation>
    <operation name="SayHello">
      <input name="SayHelloTo" message="xsd1:SayHelloToSoapIn" />
      <output name="SayHelloTo" message="xsd1:SayHelloToSoapOut" />
    </operation>
  </portType>
  <portType name="EGatewayHttpGet">
    <operation name="ProcessBase64Request">
      <input message="xsd1:ProcessBase64RequestHttpGetIn" />
      <output message="xsd1:ProcessBase64RequestHttpGetOut" />
    </operation>
    <operation name="ProcessDimeRequest">
      <input message="xsd1:ProcessDimeRequestHttpGetIn" />
      <output message="xsd1:ProcessDimeRequestHttpGetOut" />
    </operation>
    <operation name="ProcessDimeTestRequest">
      <input message="xsd1:ProcessDimeTestRequestHttpGetIn" />
      <output message="xsd1:ProcessDimeTestRequestHttpGetOut" />
    </operation>
    <operation name="SayHello">
      <input name="SayHelloTo" message="xsd1:SayHelloToHttpGetIn" />
      <output name="SayHelloTo" message="xsd1:SayHelloToHttpGetOut" />
    </operation>
  </portType>
  <portType name="EGatewayHttpPost">
    <operation name="ProcessBase64Request">
      <input message="xsd1:ProcessBase64RequestHttpPostIn" />
      <output message="xsd1:ProcessBase64RequestHttpPostOut" />
    </operation>
    <operation name="ProcessDimeRequest">
      <input message="xsd1:ProcessDimeRequestHttpPostIn" />
      <output message="xsd1:ProcessDimeRequestHttpPostOut" />
    </operation>
    <operation name="ProcessDimeTestRequest">
      <input message="xsd1:ProcessDimeTestRequestHttpPostIn" />
      <output message="xsd1:ProcessDimeTestRequestHttpPostOut" />
    </operation>
    <operation name="SayHello">
      <input name="SayHelloTo" message="xsd1:SayHelloToHttpPostIn" />
      <output name="SayHelloTo" message="xsd1:SayHelloToHttpPostOut" />
    </operation>
  </portType>
  <binding name="EGatewaySoap" type="xsd1:EGatewaySoap">
    <soap:binding transport="http://schemas.xmlsoap.org/soap/http" style="document" />
    <operation name="ProcessBase64Request">
      <soap:operation soapAction="http://tempuri.org/ProcessBase64Request" style="document" />
      <input>
        <soap:body use="literal" />
      </input>
      <output>
        <soap:body use="literal" />
      </output>
    </operation>
    <operation name="ProcessDimeRequest">
      <soap:operation soapAction="http://tempuri.org/ProcessDimeRequest" style="document" />
      <input>
        <soap:body use="literal" />
      </input>
      <output>
        <soap:body use="literal" />
      </output>
    </operation>
    <operation name="ProcessDimeTestRequest">
      <soap:operation soapAction="http://tempuri.org/ProcessDimeTestRequest" style="document" />
      <input>
        <soap:body use="literal" />
      </input>
      <output>
        <soap:body use="literal" />
      </output>
    </operation>
    <operation name="SayHello">
      <soap:operation soapAction="http://tempuri.org/SayHelloTo" style="document" />
      <input name="SayHelloTo">
        <soap:body use="literal" />
      </input>
      <output name="SayHelloTo">
        <soap:body use="literal" />
      </output>
    </operation>
  </binding>
  <binding name="EGatewayHttpGet" type="xsd1:EGatewayHttpGet">
    <http:binding verb="GET" />
    <operation name="ProcessBase64Request">
      <http:operation location="/ProcessBase64Request" />
      <input>
        <http:urlEncoded />
      </input>
      <output>
        <mime:mimeXml part="Body" />
      </output>
    </operation>
    <operation name="ProcessDimeRequest">
      <http:operation location="/ProcessDimeRequest" />
      <input>
        <http:urlEncoded />
      </input>
      <output>
        <mime:mimeXml part="Body" />
      </output>
    </operation>
    <operation name="ProcessDimeTestRequest">
      <http:operation location="/ProcessDimeTestRequest" />
      <input>
        <http:urlEncoded />
      </input>
      <output>
        <mime:mimeXml part="Body" />
      </output>
    </operation>
    <operation name="SayHello">
      <http:operation location="/SayHelloTo" />
      <input name="SayHelloTo">
        <http:urlEncoded />
      </input>
      <output name="SayHelloTo">
        <mime:mimeXml part="Body" />
      </output>
    </operation>
  </binding>
  <binding name="EGatewayHttpPost" type="xsd1:EGatewayHttpPost">
    <http:binding verb="POST" />
    <operation name="ProcessBase64Request">
      <http:operation location="/ProcessBase64Request" />
      <input>
        <mime:content type="application/x-www-form-urlencoded" />
      </input>
      <output>
        <mime:mimeXml part="Body" />
      </output>
    </operation>
    <operation name="ProcessDimeRequest">
      <http:operation location="/ProcessDimeRequest" />
      <input>
        <mime:content type="application/x-www-form-urlencoded" />
      </input>
      <output>
        <mime:mimeXml part="Body" />
      </output>
    </operation>
    <operation name="ProcessDimeTestRequest">
      <http:operation location="/ProcessDimeTestRequest" />
      <input>
        <mime:content type="application/x-www-form-urlencoded" />
      </input>
      <output>
        <mime:mimeXml part="Body" />
      </output>
    </operation>
    <operation name="SayHello">
      <http:operation location="/SayHelloTo" />
      <input name="SayHelloTo">
        <mime:content type="application/x-www-form-urlencoded" />
      </input>
      <output name="SayHelloTo">
        <mime:mimeXml part="Body" />
      </output>
    </operation>
  </binding>
  <service name="EGateway">
    <port name="EGatewaySoap" binding="xsd1:EGatewaySoap">
      <soap:address location="http://%%HOST%%:%%PORT%%/EGateway/EGateway.asmx" />
    </port>
    <port name="EGatewayHttpGet" binding="xsd1:EGatewayHttpGet">
      <http:address location="http://%%HOST%%:%%PORT%%/EGateway/EGateway.asmx" />
    </port>
    <port name="EGatewayHttpPost" binding="xsd1:EGatewayHttpPost">
      <http:address location="http://%%HOST%%:%%PORT%%/EGateway/EGateway.asmx" />
    </port>
  </service>
</definitions>
