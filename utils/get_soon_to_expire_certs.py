import ConfigParser
from comodo import certificate_service

if __name__ == "__main__":
    settings = ConfigParser.RawConfigParser()
    settings.read('example.conf')
    service = certificate_service.getComodoReportsService(settings)

    # TODO: Make this into a function, that takes a parameter "days"
    # TODO: Make the date ranges go from today - today + days (see datetime.timedelta)
    # TODO: Parse the result and print it out as CSV
    print service.getSSLReport(
        startDate="2013-02-01T00:00:00",
        endDate="2013-02-12T00:00:00",
        certificateStatus=service.CERTIFICATE_STATUSES["Any"],
        certificateDate=service.CERTIFICATE_DATE_SELECTION["Expire Date"],
        )
