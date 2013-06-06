#!/usr/bin/python
"""Comodo SSL Certificate API wrapper class
"""
__author__ = "Edward Delaporte <delaport@illinois.edu>, University of Illinois"
__copyright__ = "Copyright (C) 2011-2013 University of Illinois Board of Trustees. All rights reserved."
__license__ = "University of Illinois/NCSA Open Source License"

import suds


class CertificateServiceError(Exception):
    pass


class RequestFailedError(CertificateServiceError):
    pass


class NotReadyError(CertificateServiceError):
    pass


def getComodoSSLService(settings):
    """Return a ComodoSSLService instance.
    @param settings: a ConfigParser instance containing the following keys:
        [comodo]
        org_id=...
        api_key=...
        user=...
        password=...
        login_uri=...
        revoke_phrase=...
    """
    org_id = settings.get('comodo', 'org_id')
    api_key = settings.get('comodo', 'api_key')
    user = settings.get('comodo', 'user')
    password = settings.get('comodo', 'password')
    login_uri = settings.get('comodo', 'login_uri')
    revoke_phrase = settings.get('comodo', 'revoke_phrase')

    service = ComodoSSLService(
        org_id=org_id,
        api_secret_key=api_key,
        user=user,
        password=password,
        login_URI=login_uri,
        revoke_phrase=revoke_phrase,
    )
    return service


def getComodoReportsService(settings):
    """Return a ComodoReportsService instance.
    @param settings - a ConfigParser instance containing the following keys:
    [comodo]
    org_id=...
    user=...
    password=...
    login_uri=...
    wsdl=...
    """
    org_id = settings.get('comodo', 'org_id')
    user = settings.get('comodo', 'user')
    password = settings.get('comodo', 'password')
    login_uri = settings.get('comodo', 'login_uri')
    WSDL = settings.get('comodo', 'wsdl')

    service = ComodoReportsService(
        org_id=org_id,
        user=user,
        password=password,
        login_URI=login_uri,
        WSDL=WSDL,
    )
    return service


SERVER_APACHE = 2
SERVER_IIS = 14
WEB_SSL_CERT = "InCommon SSL"


class ComodoBaseService(object):
    """Base class for the Comodo services.

    TODO: Figure out what else needs to go here.
    """

    # Notice the extra spaces...stay classy Comodo
    AVAILABLE_CERTIFICATE_TYPES = [
        "InCommon SSL",
        "InCommon Intranet SSL",
        "InCommon Wildcard SSL Certificate ",
        "InCommon Multi Domain SSL ",
        "InCommon Unified Communications Certificate",
        "Comodo EV SGC SSL ",
        "Comodo EV Multi Domain SSL",
    ]

    CERTIFICATE_STATUSES = {
        "Any": 0,
        "Requested": 1,
        "Enrolled - Downloaded": 2,
        "Revoked": 3,
        "Expired": 4,
        "Enrolled - Pending Download": 5,
        "Not Enrolled": 6,
    }

    CERTIFICATE_DATE_SELECTION = {
        "Enrolled Date": 0,
        "Downloaded Date": 1,
        "Revoked Date": 2,
        "Expire Date": 3,
        "Requested Date": 4,
        "Issued Date": 5,
    }

    def raiseError(self, result):
        """Convert the result into something a bit more Pythonic.
        """
        if -7 < result < 0:
            raise RequestFailedError("The request could not be processed. (%d)" % result)
        if result == -14:
            raise RequestFailedError("Comodo API error. The Comodo service may be down. (%d)" % result)
        if result == -16 or result == -120:
            raise ValueError("Insufficient privileges.(%d)" % result)
        if result == -20:
            raise RequestFailedError("The certificate request has been rejected.(%d)" % result)
        if result == -21:
            raise RequestFailedError("The certificate has been revoked.(%d)" % result)
        if result == -22:
            raise RequestFailedError("Payment error.(%d)" % result)
        if result == -34:
            raise RequestFailedError("The secret key is invalid.(%d)" % result)
        if result == -40:
            raise RequestFailedError(
                "Invalid Certificate ID (Order IDs are not Certificate IDs). " +
                "Certificate IDs are normally 5 characters long and only returned by the API.(%d)" % result)
        if result == -100:
            raise ValueError("Invalid login or password.(%d)" % result)
        if result == -101:
            raise ValueError("Invalid organization credentials.(%d)" % result)
        if result == -110 or result == -111:
            raise ValueError("Illegal domain requested.(%d)" % result)
        raise ValueError("An unknown error occurred. See Comodo API documents for error number %s." % result)


class ComodoSMIMEService(ComodoBaseService):
    """Placeholder --- Not implemented service consumer for the Comodo SMIME certificate API."""

    def __init__(self, org_id, api_secret_key, user, password, login_URI,
                 WSDL="https://cert-manager.com/ws/EPKIManager?wsdl"):
        self.OrgID = org_id
        self.SecretKey = api_secret_key
        self.WSDL = WSDL
        self.Client = suds.client.Client(self.WSDL)

        self.SOAP = self.Client.service
        self.Factory = self.Client.factory
        self.Auth = self.Factory.create('authData')
        self.Auth.customerLoginUri = login_URI
        self.Auth.login = user
        self.Auth.password = password
        self.Debug = False

    def request(self, csr, name, email):
        raise NotImplementedError("S/MIME API service is not implemented yet.")


class ComodoReportsService(ComodoBaseService):
    """Service consumer for the Comodo reports web services API."""

    def __init__(self, org_id, user, password, login_URI="InCommon",
                 WSDL="https://cert-manager.com/ws/EPKIManagerSSL?wsdl"):
        """
        @org_id Comodo customer ID
                Can be obtained from Admin UI in the
                 'Organization properties' - 'Client Cert' tab.
        @api_secret_key Secret Key for SSL
                Setting in Client Admin UI in
                'Organization properties' - 'SSL Certificates' tab.
        @user - Comodo username, must have 'Client Cert' role within CCM account.
        @password - Password for the username
        @login_URI - Per Comodo API documentation: "URI for logging into account within CCM."
        """
        # Organization identifier. Can be obtained from Admin UI
        #  - Organization properties - Client Cert tab.
        self.OrgID = org_id
        self.WSDL = WSDL
        self.Client = suds.client.Client(self.WSDL)

        self.SOAP = self.Client.service
        self.Factory = self.Client.factory
        self.Auth = self.Factory.create('authData')
        self.Auth.customerLoginUri = login_URI
        self.Auth.login = user
        self.Auth.password = password
        self.Debug = False

    def getActivityReport(self, startDate, endDate):
        """Return a list of all activity (Login, User Downloaded a Certificate, etc.)

        NOTE: Undocumented. See https://www.cert-manager.com/ws/ReportService?xsd=1

        @startDate - start of queried date range
        @endDate - end of queried date range
        """
        response = self.SOAP.getActivityReport(self.Auth, startDate, endDate)
        result = response.statusCode
        if result != 0:
            self.raiseError(result)
        return response.reports

    def getDiscoveryReport(self, startDate, endDate):
        response = self.SOAP.getDiscoveryReport(self.Auth, startDate, endDate)
        result = response.statusCode
        if result != 0:
            self.raiseError(result)
        return response

    def getSSLReport(self, startDate, endDate, organizationNames="",
                     certificateStatus=None, certificateDate=None):
        """Get a list of SSL certs that match the date criteria.

        @startDate - start of queried date range
        @endDate - end of queried date range
        @organizationNames - either an empty string for all departments, or department names, separated by commas
        @certificateStatus - status of the certificates (See CERTIFICATE_STATUSES)
        @certificateDate - type of date being queried (See CERTIFICATE_DATE_SELECTION)
        """

        if certificateStatus is None:
            certificateStatus = self.CERTIFICATE_STATUSES["Any"]

        if certificateDate is None:
            certificateDate = self.CERTIFICATE_DATE_SELECTION["Enrolled Date"]

        response = self.SOAP.getSSLReport(self.Auth, startDate, endDate, organizationNames,
                                          certificateStatus, certificateDate)
        result = response.statusCode
        if result != 0:
            self.raiseError(result)
        return response

    def getWebServiceInfo(self):
        """Get basic information about the web service (name, version, etc.)
        """

        response = self.SOAP.getWebServiceInfo()
        return response


class ComodoSSLService(ComodoBaseService):
    def __init__(self, org_id, api_secret_key, user, password,
                 revoke_phrase, login_URI='InCommon'):
        """
        @org_id Comodo customer ID
                Can be obtained from Admin UI in the
                 'Organization properties' - 'Client Cert' tab.
        @api_secret_key Secret Key for SSL
                Setting in Client Admin UI in
                'Organization properties' - 'SSL Certificates' tab.
        @user - Comodo username, must have 'Client Cert' role within CCM account.
        @password - Password for the username
        @revoke_phrase - A certificate revocation passphrase. Cannot be left blank!
        @login_URI - Per Comodo API documentation: "URI for logging into account within CCM."
        """
        # Organization identifier. Can be obtained from Admin UI
        #  - Organization properties - Client Cert tab.
        self.OrgID = org_id

        # Secret Key
        # Setting in Client Admin UI
        # Organization Properties - SSL Certificates
        self.SecretKey = api_secret_key

        self.WSDL = "https://cert-manager.com/ws/EPKIManagerSSL?wsdl"

        self.Client = suds.client.Client(self.WSDL)

        self.RevokePhrase = revoke_phrase

        self.SOAP = self.Client.service
        self.Factory = self.Client.factory
        self.Auth = self.Factory.create('authData')
        self.Auth.customerLoginUri = login_URI
        self.Auth.login = user
        self.Auth.password = password
        self.Debug = False

    def getServerType(self, server_type_name):
        """A bit of a hack to convert server type names into API keys.
        @param server_type_name: Server type name to convert to API key.
        """
        comodoServerTypes = {
            'AOL': 1,
            'Apache/ModSSL': 2,
            'Apache-ModSSL': 2,
            'Apache-SSL (Ben-SSL, not Stronghold)': 3,
            'C2Net Stronghold': 3,
            'Cisco 3000 Series VPN Concentrator': 33,
            'Citrix': 34,
            'Cobalt Raq': 5,
            'Covalent Server Software': 6,
            'IBM HTTP Server': 7,
            'IBM Internet Connection Server': 8,
            'iPlanet': 9,
            'Java Web Server (Javasoft / Sun)': 10,
            'Lotus Domino': 11,
            'Lotus Domino Go!': 12,
            'Microsoft IIS 1.x to 4.x': 13,
            'Microsoft IIS 5.x and later': 14,
            'Netscape Enterprise Server': 15,
            'Netscape FastTrac': 16,
            'Novell Web Server': 17,
            'Oracle': 18,
            'Quid Pro Quo': 19,
            'R3 SSL Server': 20,
            'Raven SSL': 21,
            'RedHat Linux': 22,
            'SAP Web Application Server': 23,
            'Tomcat': 24,
            'Website Professional': 25,
            'WebStar 4.x and later': 26,
            'WebTen (from Tenon)': 27,
            'Zeus Web Server': 28,
            'Ensim': 29,
            'Plesk': 30,
            'WHM/cPanel': 31,
            'H-Sphere': 32,
            'OTHER': -1,
        }

        if server_type_name in comodoServerTypes.keys():
            return comodoServerTypes[server_type_name]
        else:
            return None

    def request(self, csr, fqdns=None, years=1, server_type='Apache-ModSSL', cert_type='InCommon SSL'):
        """Request a new SSL certificate from Comodo.

        @csr Certificate Signing Request
        @fqdns fully qualified domain names
        @serverType SERVER_APACHE or SERVER_IIS

        @return Comodo Certificate ID

        """
        if not fqdns:
            fqdns = []

        serverType = self.getServerType(server_type)

        certTypes = self.getCertTypes()
        certType = None

        for ct in certTypes:
            if ct.name.strip() == cert_type.strip():
                certType = ct
        if certType is None:
            raise Exception("A Comodo API error occurred. Requested certificate type %s is not available." % cert_type)

        data = {
            'authData': self.Auth,
            'orgId': int(self.OrgID),
            'secretKey': self.SecretKey,
            'csr': csr,
            'phrase': self.RevokePhrase,
            'subjAltNames': ','.join(fqdns),
            'certType': certType,
            'numberServers': 1,
            'serverType': serverType,
            'term': years,
            'comments': "",
        }

        # print "Data passed to Enroll: %s" % str(data)

        result = self.SOAP.enroll(
            data['authData'],
            data['orgId'],
            data['secretKey'],
            data['csr'],
            data['phrase'],
            data['subjAltNames'],
            data['certType'],
            data['numberServers'],
            data['serverType'],
            data['term'],
            data['comments'],
        )

        if result < 0:
            self.raiseError(result)
        else:
            return result

    def getCertTypes(self):
        """Returns the certificate types available to the current user."""
        response = self.SOAP.getCustomerCertTypes(self.Auth)
        result = response.statusCode
        if result != 0:
            self.raiseError(result)
        return response.types

    def renew(self, certId):
        """Request renewal of an SSL certificate previously issued from Comodo.
        @certId Comodo CCM certificate id
        @return True if the renewal was successfully submitted.
        """
        result = self.SOAP.renew(certId)
        # result = response.statusCode
        if result == 0:
            return True
        if result == -4:
            raise ValueError("Invalid Comodo Certificate ID: %s" % certId)
        if result == -3:
            raise RequestFailedError("Comodo API error. The Comodo service may be down.")
        else:
            self.raiseError(result)
            return False

    def collect(self, certId):
        """Collect the SSL certificate from Comodo.
        @param certId: Comodo CCM certificate id
        """
        response = self.SOAP.collect(
            self.Auth,
            certId,
            formatType=1
        )

        result = response.statusCode
        if result < 0:
            self.raiseError(result)
        if result == 0:
            return None, None
        ssl = response.SSL

        cert = ssl['certificate']
        order_id = ssl['renewID']
        return order_id, cert

    def collectRenewed(self, renewId):
        response = self.SOAP.collect(
            renewId,
            formatType=1
        )
        result = response.statusCode
        if result < 0:
            self.raiseError(result)
        ssl = response.SSL
        cert = ssl['certificate']
        order_id = ssl['renewID']
        return order_id, cert

    def certReady(self, certId):
        """Return True if the requested SSL certificate is finished processing and available from Comodo.
        @certId Comodo CCM certificate id
        """
        result = self.SOAP.getCollectStatus(self.Auth, certId)
        if result == 1:
            return True
        if result == 0:
            return False
        else:
            self.raiseError(result)
