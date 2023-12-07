# snippets/models.py
from django.db import models
from django import forms
from pygments.lexers import get_all_lexers
from pygments.styles import get_all_styles
from django.contrib.postgres import fields
from django.contrib.postgres.fields import ArrayField
from django.contrib.auth.models import User

from datetime import datetime
import uuid
from django.contrib.postgres.fields import JSONField
from django.conf import settings
from django.conf.urls.static import static

Choices_Severity= [
('info, low, medium, high, critical, unknown', 'All'),
 ('info', 'Info'),
 ('low', 'Low'),
 ('medium', 'Medium'),
 ('high', 'High'),
 ('critical', 'Critical'),
 ('unknown', 'Unknown')
 ]

Choices_APIProviders= [
    ('nessus', 'Nessus'),
    ('google', 'Google'),
    ('censys', 'Censys'),
    ('shodan', 'Shodan'),
    ('burp', 'Burp'),
    ('yahoo', 'Yahoo'),
    ('other', 'Other')
    ]

choices_request_methods= [
    ('none', 'None'),
    ('connect', 'CONNECT'),
    ('delete', 'DELETE'),
    ('get', 'GET'),
    ('head', 'HEAD'),
    ('options', 'OPTIONS'),
    ('post', 'POST'), 
    ('put', 'PUT'),
    ('trace', 'TRACE')
    ]

##############################
######## customers
##############################
class Customers(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, help_text='The unique identifier for the model.')
    groupingProject = models.CharField(max_length=100, default='Ego', help_text='Please provide the group\'s name (e.g. BugCrowd, Hackerone, or WorkPlace).')
    nameProject = models.CharField(unique=True, max_length=100, default='Please name the project.', help_text='Please provide a covert name for the project. This will help keep your project a secret from other users.')
    nameCustomer = models.CharField(unique=True, max_length=100, default='Please the customers name.', help_text='The real name of the customer. This is a secret.')
    URLCustomer = models.CharField(max_length=2048, default='Please the customers name.', help_text='The main URL for the customer, or the BugBounty URL to the customer platform.')
    dateCreated = models.DateTimeField(auto_now_add=True, blank=True, editable=False, help_text='The date and time when the model was created.')
    customDaysUntilNextScan = models.IntegerField(default=30, help_text='The number of days until the next scan.')
    toScanDate = models.DateField(blank=True, null=True, help_text='The date when the next scan is scheduled.')
    endToScanDate = models.DateField(blank=True, null=True, help_text='The date when the last scan is scheduled.')
    lastEgoScan = models.DateField(blank=True, null=True, help_text='The date of the last Ego scan.')
    EgoReconScan = models.BooleanField(default=False, help_text='Whether or not to perform an Ego recon scan.')
    reconOnly = models.BooleanField(default=False, help_text='Whether or not to perform a recon-only attack.')
    passiveAttack = models.BooleanField(default=False, help_text='Whether or not to perform a passive attack.')
    aggressiveAttack = models.BooleanField(default=False, help_text='Whether or not to perform an aggressive attack.')
    notes = models.TextField(blank=True, default='Nothing to tell here.', help_text='Any additional notes about the model.')
    OutOfScopeString = models.CharField(max_length=75, blank=True, null=True, help_text='This is a list of...')
    urlScope = fields.ArrayField(models.URLField(max_length=2048), blank=True, default=list, help_text='The URLs in scope.')
    outofscope = fields.ArrayField(models.CharField(max_length=256), blank=True, default=list, help_text='The items out of scope.')
    domainScope = fields.ArrayField(models.CharField(max_length=256), blank=True, default=list, help_text='The domains in scope.')
    Ipv4Scope = fields.ArrayField(models.CharField(max_length=256), blank=True, default=list, help_text='The IPv4 addresses in scope.')
    Ipv6Scope = fields.ArrayField(models.CharField(max_length=256), blank=True, default=list, help_text='The IPv6 addresses in scope.')
    FoundTLD = fields.ArrayField(models.CharField(max_length=256), blank=True, default=list, help_text='The top-level domains found.')
    FoundASN = fields.ArrayField(fields.ArrayField(models.CharField(max_length=256)), blank=True, default=list, help_text='The autonomous system numbers found.')
    skipScan = models.BooleanField(default=False, help_text='Whether or not to skip the scan.')
    def __unicode__(self):
        return self.nameProject

##############################
######## Records
##############################
class Record(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    customer_id = models.ForeignKey(Customers, on_delete=models.CASCADE, related_name='customer_records', blank=True)
    md5 = models.CharField(max_length=32, unique=True)
    domainname = models.CharField(max_length=256, blank=True) 
    subDomain = models.CharField(max_length=256, blank=True, unique=True)
    #scanSevirity = models.CharField(max_length=256, blank=True, default='none')
    dateCreated = models.DateTimeField(auto_now_add=True)
    lastScan = models.DateField(auto_now_add=True)
    skipScan = models.BooleanField(default='False')
    alive = models.BooleanField(default='False')
    nucleiBool = models.BooleanField(default='False')
    ip = fields.ArrayField(models.CharField(max_length=256), blank=True, default=list)
    Ipv6Scope = fields.ArrayField(models.CharField(max_length=256), blank=True, default=list)
    OpenPorts = models.JSONField(default=list, blank=True)
    CertBool = models.BooleanField(default='False', blank=True)
    CMS = models.CharField(max_length=256, blank=True)
    ASN = ArrayField(ArrayField(models.CharField(max_length=2048), blank=True), default=list)
    Images= models.ImageField(upload_to='RecordPictures', blank=True)
    #whoIs = models.JSONField(default=dict, blank=True)

class GEOCODES(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    record_id = models.ForeignKey(Record, on_delete=models.CASCADE, related_name='GEOCODES')
    ip_address = models.CharField(max_length=256, blank=True)
    city = models.CharField(max_length=256, blank=True)
    region = models.CharField(max_length=256, blank=True)
    country = models.CharField(max_length=256, blank=True)
    latitude = models.CharField(max_length=256, blank=True)
    longitude = models.CharField(max_length=256, blank=True)

##############################
# NMap NIST 
##############################
class CPEID(models.Model):
    cpeId = models.CharField(max_length=175, primary_key=True)
    CPE = models.CharField(max_length=100)
    service = models.CharField(max_length=75)
    version = models.CharField(max_length=128)

class csv_version(models.Model):
    vectorString = models.CharField(primary_key=True, max_length=50)
    version = models.CharField(max_length=7)
    accessVector = models.CharField(max_length=50)
    accessComplexity = models.CharField(max_length=9)
    authentication = models.CharField(max_length=256)
    confidentialityImpact = models.CharField(max_length=10)
    integrityImpact = models.CharField(max_length=10)
    availabilityImpact = models.CharField(max_length=10)
    baseScore = models.CharField(max_length=5)
    baseSeverity = models.CharField(max_length=9)

class nist_description(models.Model):
    nist_record_id = models.ForeignKey(Record, on_delete=models.CASCADE, related_name='Nist_records', blank=True, null=True)
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    CPEServiceID = models.ForeignKey(CPEID, on_delete=models.CASCADE, related_name='CPEService')
    csv_version_id = models.ForeignKey(csv_version, on_delete=models.CASCADE, related_name='CsvVersion')
    CPE = models.CharField(max_length=100)
    service = models.CharField(max_length=75)
    descriptions = models.TextField(unique=True)
    references = ArrayField(models.CharField(max_length=2048), blank=True)

class ThreatModeling(models.Model): 
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    customer = models.ForeignKey(Customers, on_delete=models.CASCADE, related_name='customer_threat_modeling')

class TldIndex(models.Model):
    tld = models.CharField(unique=True, max_length=256)
    count = models.IntegerField(blank=True)

class Nmap(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    record_id = models.ForeignKey(Record, on_delete=models.CASCADE, related_name='Nmaps_record')
    #nmapNistVulns = models.ForeignKey(nist_description, on_delete=models.CASCADE, related_name='nmapNistVulns', blank=True, default = None)
    md5 = models.CharField(max_length=500, unique=True)
    date = models.DateTimeField(auto_now_add=True, blank=True)
    name = models.CharField(max_length=500, blank=True)
    port = models.CharField(max_length=500, blank=True)
    protocol = models.CharField(max_length=500, blank=True)
    service = models.JSONField(default=dict, blank=True)
    state = models.CharField(max_length=10, blank=True)
    hostname = models.JSONField(default=list, blank=True)
    macaddress = models.CharField(max_length = 50, blank=True)
    reason =models.CharField(max_length = 500, blank=True)
    reason_ttl = models.CharField(max_length = 500, blank=True)
    service=models.CharField(max_length = 500, blank=True)
    cpe= models.CharField(max_length = 500, blank=True)
    scripts= models.JSONField(default=list, blank=True)
    conf = models.CharField(max_length = 500, blank=True)
    extrainfo = models.CharField(max_length = 500, blank=True)
    method = models.CharField(max_length = 500, blank=True)
    ostype = models.CharField(max_length = 500, blank=True)
    product = models.CharField(max_length = 500, blank=True)
    version = models.CharField(max_length = 500, blank=True)
    servicefp = models.TextField(blank=True)

##############################
######## Control
##############################
class GnawControl(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    NucleiScan = models.BooleanField(default='True')
    Ipv_Scan = models.BooleanField(default='False')
    LoopCustomersBool = models.BooleanField(default='False')
## fix in next updatee to support list of strings to ignore
    OutOfScope = models.CharField(max_length = 75, blank=True, null=True)
    ScanProjectByID = models.CharField(max_length = 75, blank=True, help_text='<fieldset style="background-color: lightblue;display: inline-block;">Please provide the groups name example BugCrowd, Hackerone, or WorkPlace</fieldset>')
    ScanGroupingProject = models.CharField(max_length = 75, blank=True, help_text='<fieldset style="background-color: lightblue;display: inline-block;">Please provide a Covert Name for the project, this will help keep your project a secret from other users.</fieldset>')
    ScanProjectByName = models.CharField(max_length = 75, blank=True, help_text='<fieldset style="background-color: lightblue;display: inline-block;">The real name of the customer, this is a secret</fieldset>')
    Customer_chunk_size = models.IntegerField(default='7', help_text='<fieldset style="background-color: lightblue;display: inline-block;">The main url for the customer, or the BugBounty url to the customer platform. </fieldset>')
    Record_chunk_size = models.IntegerField(default='20', help_text='<fieldset style="background-color: lightblue;display: inline-block;">Default is false, this will tell the engine\'s to skip this target if an <b>All Customer scan</b> is ran.</fieldset>')
    Global_Nuclei_CoolDown= fields.ArrayField(models.IntegerField(default='2'), blank=True)
    Global_Nuclei_RateLimit= models.IntegerField(default='6')
    Port = models.IntegerField(default='9000', help_text="<fieldset style=\"background-color: lightblue;display: inline-block;\">The default port number is a dragon ball reference. It is over 9000!</fieldset>")
    HostAddress = models.CharField(max_length=256, default='http://127.0.0.1', help_text="<fieldset style=\"background-color: lightblue;display: inline-block;\">The domain name of the server hosting the API, if the api is ran locally this address would be the default. </fieldset>")
    severity = models.CharField(max_length=256, default='info, low, medium, high, critical, unknown', help_text='<fieldset style="background-color: lightblue;display: inline-block;">please provide, one of the severity options to scan for or use them all. <b>Severity</b>info,</br> low,</br> medium,</br> high,</br> critical,</br> unknown</br></fieldset>')
    Gnaw_Completed = models.BooleanField(default='False', help_text='<fieldset style="background-color: lightblue;display: inline-block;">Used to scan all customers.</fieldset>')
    failed = models.BooleanField(default='False', help_text='<fieldset style="background-color: lightblue;display: inline-block;">An exception occured.</fieldset>')
    scan_objects = fields.ArrayField(models.CharField(max_length=256), blank=True, default=list)

class EgoControl(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    ScanProjectByID = models.CharField(max_length = 75, blank=True, help_text='<fieldset style="background-color: lightblue;display: inline-block;">The uniquic identifier stirng assigned to id Objects.</fieldset>')
    internal_scanner = models.BooleanField(default='False')
    ScanGroupingProject = models.CharField(max_length = 75, blank=True, help_text='<fieldset style="background-color: lightblue;display: inline-block;">Example BugCrowd, HackerOne, or work. </fieldset>')
    ScanProjectByName = models.CharField(max_length = 75, blank=True, help_text='<fieldset style="background-color: lightblue;display: inline-block;">The projects code, name. </fieldset>')
    OutOfScope = models.CharField(max_length = 75, blank=True, null=True, help_text='')
    chunk_size= models.IntegerField(default='12', help_text='<fieldset style="background-color: lightblue;display: inline-block;">Define the scan chunksize for the records, keep in mind that a high value may lead to getting detected by the wafs. It will perform a scan in breathe but some wafs are smart and will observe slow paralle hits. A high vlaue may also consume your network cards usage, and prevent internet usage on the system.</fieldset>')
    CoolDown= models.IntegerField(default='2', help_text='<fieldset style="background-color: lightblue;display: inline-block;">Accepts a tuple example (1,34), this will define the range for the timeout between customer scans.</fieldset>')
    CoolDown_Between_Queries= models.IntegerField(default='6', help_text='<fieldset style="background-color: lightblue;display: inline-block;">Accepts a tuple example (1,34), this will define the range for the timeout between customer scans. </fieldset>')
    Port = models.IntegerField(default='9000', help_text='<fieldset style="background-color: lightblue;display: inline-block;">Example 5000</fieldset>')
    HostAddress = models.CharField(max_length=256, default='127.0.0.1', help_text='<fieldset style="background-color: lightblue;display: inline-block;">Please provide the full url including protocol schema example https://google.com, for where the api is hsoted</fieldset>')
    passiveAttack = models.BooleanField(default='False', help_text='<fieldset style="background-color: lightblue;display: inline-block;">Passive scans is not active at this time.</fieldset>')
    agressiveAttack = models.BooleanField(default='False', help_text='<fieldset style="background-color: lightblue;display: inline-block;">Passive scans is not active at this time.</fieldset>')
    portscan_bool = models.BooleanField(default='False', help_text='<fieldset style="background-color: lightblue;display: inline-block;">agressive scan is not active at this time.</fieldset>')
    versionscan_bool = models.BooleanField(default='False', help_text='<fieldset style="background-color: lightblue;display: inline-block;">Tell the engine to perform a port scan, by default EGO uses a predfined list of ports. this feature will be expanded later to allow customer port ranges.</fieldset>')
    Scan_Scope_bool = models.BooleanField(default='False')
    Scan_IPV_Scope_bool = models.BooleanField(default='False')
    Scan_DomainName_Scope_bool = models.BooleanField(default='False')
    scriptscan_bool = models.BooleanField(default='False')
    BruteForce = models.BooleanField(default='False')
    BruteForce_WL = fields.ArrayField(models.CharField(max_length=256), blank=True, default=list)
    scan_records_censys = models.BooleanField(default='False')
    crtshSearch_bool = models.BooleanField(default='False')
    Update_RecordsCheck = models.BooleanField(default='False')
    LoopCustomersBool = models.BooleanField(default='False')
    #Start = models.BooleanField(default='False')
    #StartBy = models.DateTimeField(auto_now_add=True, blank=True)
    #pause = models.BooleanField(default='False')
    #pauseBy = models.DateTimeField(auto_now_add=True, blank=True)
    Completed = models.BooleanField(default='False')
    Gnaw_Completed = models.BooleanField(default='False')
    failed = models.BooleanField(default='False')
    scan_objects = fields.ArrayField(models.CharField(max_length=256), blank=True, default=list)

class MantisControls(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    NucleiScan = models.BooleanField(default='True')
    Ipv_Scan = models.BooleanField(default='False')
    LoopCustomersBool = models.BooleanField(default='False')
    OutOfScope = fields.ArrayField(models.CharField(max_length=256), blank=True, default=list)
    ScanProjectByID = models.CharField(max_length = 75, blank=True)
    ScanGroupingProject = models.CharField(max_length = 75, blank=True)
    ScanProjectByName = models.CharField(max_length = 75, blank=True)
    Customer_chunk_size = models.IntegerField(default='7')
    Record_chunk_size = models.IntegerField(default='20')
    Global_CoolDown= fields.ArrayField(models.IntegerField(default='2'), blank=True)
    Global_RateLimit= models.IntegerField(default='6')
    Port = models.IntegerField(default='9000')
    HostAddress = models.CharField(max_length=256, default='127.0.0.1')
    severity = models.CharField(max_length=256, default='info, low, medium, high, critical, unknown')
    Elavate =models.CharField(max_length=256, default='127.0.0.1')
    Mantis_Completed = models.BooleanField(default='False')
    failed = models.BooleanField(default='False')
    scan_objects = fields.ArrayField(models.CharField(max_length=256), blank=True)


##############################
##### manager/api/credentials
##############################
class projectManger(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    customer_id = models.ForeignKey(Customers, on_delete=models.CASCADE, related_name='customer_projectManger', blank=True)
    created = models.DateTimeField(auto_now_add=True, blank=True)
    lastupdated = models.DateTimeField(auto_now_add=True, blank=True)
    lastupdatedby = User.objects.filter(id=True)
    comment = models.TextField(unique=True)
    
class DocManger(models.Model): 
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)    
    projectManDoc_id = models.ForeignKey(projectManger, on_delete=models.CASCADE, related_name='projectManDoc_id')

    created = models.DateTimeField(auto_now_add=True, blank=True)
    lastupdated = models.DateTimeField(auto_now_add=True, blank=True)
    lastupdatedby = User.objects.filter(id=True)
    comment = models.TextField(unique=True)
    Files =  models.FileField(upload_to='Matrix/Files', blank=True)

class FindingMatrix(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    projectManMatrix_id = models.ForeignKey(projectManger, on_delete=models.CASCADE, related_name='projectManMatrix_id')
    found = models.CharField(max_length=500, blank=True)
    created=models.DateTimeField(auto_now_add=True, blank=True)
    updated=models.DateTimeField(auto_now_add=True, blank=True)
    type = models.CharField(max_length = 500, blank=True)
    component = models.CharField(max_length = 500, blank=True)
    seveiry = models.CharField(max_length = 500, blank=True)
    compelxity = models.CharField(max_length = 500, blank=True)
    risk = models.CharField(max_length = 500, blank=True)
    threat = models.CharField(max_length = 500, blank=True)
    locations = models.CharField(max_length = 500, blank=True)
    impact = models.CharField(max_length = 500, blank=True)
    details = models.TextField(blank=True)
    example_location = fields.ArrayField(models.CharField(max_length=1024), blank=True, default=list)
    remediation = models.TextField(blank=True)
    references = fields.ArrayField(models.CharField(max_length=1024), blank=True, default=list)
    Images= models.ImageField(upload_to='RecordPictures/', blank=True)
    Files =  models.FileField(upload_to='Matrix/Files', blank=True)

class apiproviders(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(choices=Choices_APIProviders, max_length=100, default='unknown', unique=True)

class api(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    apiproviders_id = models.ForeignKey(apiproviders, on_delete=models.CASCADE, related_name='ApiProviders', blank=True)
    dateCreated = models.DateTimeField(auto_now_add=True, blank=True, editable=False)
    lastScan = models.DateField(auto_now_add=True)
    whentouse = models.IntegerField(default='30')
    apiId = models.TextField(blank=True)
    apiKey = models.TextField(blank=True)
    passWord = models.CharField(max_length=256, blank=True)
    userName = models.CharField(max_length=256, blank=True)
    inuse = models.BooleanField(default='False')

class Credential(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    credential = models.ForeignKey(Customers, on_delete=models.CASCADE, related_name='credentials_customers', null=True)
    dateCreated = models.DateTimeField(auto_now_add=True, blank=True, editable=False)
    domainname = models.URLField(max_length = 2048)
    username = models.CharField(max_length=256)
    password = models.CharField(max_length=256)


##############################
##### data systems
##############################
class RequestMetaData(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    record_id = models.ForeignKey(Record, on_delete=models.CASCADE, related_name='RecRequestMetaData')
    md5 = models.CharField(max_length=32, unique=True)
    status = models.CharField(max_length = 3)
    redirect = models.BooleanField(default='False')
    paths = fields.ArrayField(models.CharField(max_length = 2048), blank=True )
    cookies = models.JSONField(blank=True)
    headers = models.JSONField(blank=True)
    backend_headers = models.JSONField(default=list, blank=True)
    FoundObjects = models.JSONField(default=list, blank=True)
    headerValues = models.JSONField(default=list, blank=True)
    htmlValues = models.JSONField(default=list, blank=True)
    rawHTML = models.TextField(blank=True)
    #content_length = models.CharField(max_length=7, unique=True)
    
class whois(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    customer_id = models.ForeignKey(Customers, on_delete=models.CASCADE, related_name='whois_customers', blank=True)
    domain_name = fields.ArrayField(models.CharField(max_length=256), blank=True, default=list)
    registrar = models.CharField(max_length=254, blank=True, null=True)
    whois_server = models.CharField(max_length=254, blank=True, null=True)
    referral_url = models.CharField(max_length=254, blank=True, null=True)
    updated_date = models.CharField(max_length=254, blank=True)
    creation_date = fields.ArrayField(models.CharField(max_length=30), blank=True, null=True)
    expiration_date = fields.ArrayField(models.CharField(max_length=30), blank=True, null=True)
    name_servers = fields.ArrayField(models.CharField(max_length=256), blank=True, null=True)
    status = fields.ArrayField(models.CharField(max_length=175), blank=True, null=True)
    emails = fields.ArrayField(models.EmailField(max_length=254), blank=True, null=True)
    dnssec = fields.ArrayField(models.CharField(max_length=500), blank=True, null=True)
    name = models.CharField(max_length=254, blank=True, null=True)
    org = models.CharField(max_length=254, blank=True, null=True)
    registrant_postal_code = models.CharField(max_length=254, blank=True, null=True)
    address = models.CharField(max_length=254, blank=True, null=True)
    city = models.CharField(max_length=254, blank=True, null=True)
    state = models.CharField(max_length=254, blank=True, null=True)
    registrant_postal_code = models.CharField(max_length=254, blank=True, null=True)
    country = models.CharField(max_length=4, blank=True, null=True)

class Certificate(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    record_id = models.ForeignKey(Record, on_delete=models.CASCADE, related_name='Certificates_record')
    md5 = models.CharField(max_length=32, unique=True)
    countryName = models.TextField(blank=True)
    stateOrProvinceName = models.TextField(blank=True)
    organizationName = models.TextField(blank=True)
    localityName = models.TextField(blank=True)
    subjectAltName = fields.ArrayField(models.CharField(max_length=256), blank=True)
    OCSP = models.URLField(max_length = 2048, blank=True)
    caIssuers = models.URLField(max_length = 2048, blank=True)
    crlDistributionPoints = models.URLField(max_length = 2048, blank=True)
    PEM = models.TextField(blank=True)

class DNSQuery(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    record_id = models.ForeignKey(Record, on_delete=models.CASCADE, related_name='DNSQuery_record')
    md5 = models.CharField( max_length=32, unique=True)
    A = models.GenericIPAddressField(protocol="IPv4", blank=True, null=True)
    AAAA = models.CharField(max_length=500, blank=True)
    #AAAA = models.GenericIPAddressField(protocol="IPv6", blank=True, null=True)
    NS = models.TextField(blank=True)
    CNAME = models.TextField(blank=True)
    r = models.TextField(blank=True)
    MX = models.TextField(blank=True)
    TXT = models.TextField(blank=True)
    ANY = models.TextField(blank=True)

class DNSAuthority(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    record_id = models.ForeignKey(Record, on_delete=models.CASCADE, related_name='DNSAuthority_record')
    md5 = models.CharField( max_length=32, unique=True)
    A = models.GenericIPAddressField(protocol="IPv4", blank=True, null=True)
    #AAAA = models.GenericIPAddressField(protocol="IPv6", blank=True, null=True)
    AAAA = models.CharField(max_length=500, blank=True)
    NS = models.TextField(blank=True)
    CNAME = models.CharField(max_length = 2048, blank=True)
    r = models.CharField(max_length=500, blank=True)
    MX = models.TextField(blank=True)
    TXT = models.TextField(blank=True)
    ANY = models.CharField(max_length=500, blank=True)

class Template(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    record_id = models.ForeignKey(Record, on_delete=models.CASCADE, related_name='Templates_record')
    date = models.DateTimeField(auto_now_add=True, null=True)
    md5 = models.CharField(max_length=32, unique=True)
    template = models.CharField(max_length=2048, null=True)
    template_url = models.URLField(max_length = 2048, null=True)
    template_id = models.CharField(max_length=500, null=True)
    info = models.JSONField(default=list, null=True)
    host = models.CharField(max_length=256, null=True)
    matched_at = models.TextField(blank=True, default='False', null=True)
    matcher_status = models.BooleanField(default='False')
    matched_line = models.BooleanField(default='False')
    matcher_status = models.BooleanField(default='False')
    timestamp = models.DateTimeField(null=True)
    extracted_results = fields.ArrayField(models.CharField(max_length=2048), null=True)
    curl_command = models.TextField(blank=True, null=True)
    Submitted = models.BooleanField(default='False')

class External_Internal_Checklist(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    Grouping = models.CharField(max_length=100, default='Ego') 
    tool = models.DateField(auto_now_add=True)
    tester = models.CharField(max_length=100, default='Ego') 
    date = models.DateTimeField(auto_now_add=True, blank=True, editable=False)
    status = models.BooleanField(default='False')
    notes = models.TextField(blank=True)
    
class WordListGroup(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    groupName = models.CharField( max_length=256 )
    type = models.CharField(max_length=32)
    description = models.TextField(blank=True, default='It may seem dumb but add some context')
    count = models.CharField( max_length=20, blank=True )
    def __unicode__(self):
        return self.groupName

class WordList(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    WordList = models.ForeignKey(WordListGroup, on_delete=models.CASCADE, related_name='WordList')
    type = models.CharField(max_length=32, default="None", blank=True)
    Value = models.CharField(unique=True, max_length=2024)
    Occurance = models.IntegerField(default=0)
    foundAt = fields.ArrayField(models.CharField(max_length=256), blank=True)
##############################
##### vulns
##############################

class Nuclei(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    record_id = models.ForeignKey(Record, on_delete=models.CASCADE, related_name='nucleiRecords_record')
    md5 = models.CharField(max_length=32, unique=True)
    date = models.DateTimeField(auto_now_add=True, blank=True)
    name = models.CharField(max_length=500, blank=True)
    method = models.CharField(max_length=20, blank=True)
    #severity = models.CharField(choices=Choices_Severity, max_length=8, default='unknown')
    vulnerable = models.URLField(max_length = 2048, blank=True)

class VulnCard(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=256, unique=True, blank=True)
    vulnClass = models.CharField(max_length=256, null=True)
    author = fields.ArrayField(models.CharField(max_length = 125, blank=True), null=True)
    severity = models.CharField(choices=Choices_Severity, max_length=120, default='unknown')
    cvss_metrics = models.CharField(max_length=256, blank=True)
    cvss_score = models.CharField(max_length=10, blank=True)
    cwe_id = models.CharField(max_length=256, blank=True)
    description = models.TextField(blank=True)
    impact = models.TextField(blank=True)
    proof_of_concept = models.TextField(blank=True)
    remediation = models.TextField(blank=True)
    references = fields.ArrayField(models.URLField(max_length = 2048), blank=True)
    pictures = models.ImageField(upload_to='ProofOfConcept', blank=True)

class FoundVuln(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    vuln_cardId = models.ForeignKey(VulnCard, on_delete=models.CASCADE, related_name='vuln_cardId', blank=True, null=True)
    record_id = models.ForeignKey(Record, on_delete=models.CASCADE, related_name='foundVuln_record', blank=True, null=True)
    DomainName = models.CharField(max_length=256, blank=True)
    creds = fields.ArrayField(models.CharField(max_length = 256), blank=True, null=True)
    name = models.CharField(max_length=256, blank=True)
    author = fields.ArrayField(models.CharField(max_length = 125), blank=True)
    severity = models.CharField(choices=Choices_Severity, max_length=120, default='unknown')
    date = models.DateTimeField(auto_now_add=True, blank=True)
    vulnClass = models.CharField(max_length=256, null=True)
    cvss_metrics = models.CharField(max_length=256, blank=True)
    cvss_score = models.CharField(max_length=10, blank=True)
    cwe_id = models.CharField(max_length=256, blank=True)
    description = models.TextField(blank=True)
    impact = models.TextField(blank=True)
    proof_of_concept = models.TextField(blank=True)
    remediation = models.TextField(blank=True)
    location = fields.ArrayField(models.URLField(max_length = 2048), blank=True, null=True)
    references = fields.ArrayField(models.URLField(max_length = 2048), blank=True)
    exploitDB = fields.ArrayField(models.URLField(max_length = 2048), blank=True)
    addtional_data = models.FileField(upload_to='ProofOfConcept', blank=True)
    Submitted = models.BooleanField(default='False')
    matchers_status = models.CharField(max_length=2048, blank=True)
    match_headers = models.CharField(max_length=2048, blank=True)
    matchedAt_headers = models.CharField(max_length=2048, blank=True)
    match_bodys = models.CharField(max_length=2048, blank=True)
    matchedAt_bodys = models.CharField(max_length=2048, blank=True)
    curl_command = models.TextField(blank=True)

class FoundVulnDetails(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    FoundVuln_id =  models.ForeignKey(FoundVuln, on_delete=models.CASCADE, related_name='VulnDetails', blank=True, null=True)
    DomainName = models.CharField(max_length=256, blank=True)
    location = models.CharField(max_length=2048, blank=True,unique=True)
    date = models.DateTimeField(auto_now_add=True, blank=True)
    creds = fields.ArrayField(models.CharField(max_length=500), blank=True, null=True)
    pictures = models.ImageField(upload_to='ProofOfConcept', blank=True)
    matchers_status = models.CharField(max_length=2048, blank=True)
    match_headers = models.CharField(max_length=2048, blank=True)
    matchedAt_headers = models.CharField(max_length=2048, blank=True)
    match_bodys = models.CharField(max_length=2048, blank=True)
    matchedAt_bodys = models.CharField(max_length=2048, blank=True)
    curl_command = models.TextField(blank=True)

class PythonNuclei(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    vulnCard_id= models.ForeignKey(VulnCard, on_delete=models.CASCADE, related_name='PythonNuclei_record')
    Elevate_Vuln = models.CharField(max_length=256, blank=True)
    name = models.CharField(max_length=256, null=True)
    callbackServer =  models.CharField(max_length = 2048, default='http://127.0.0.1')
    callbackServerKey = models.CharField(max_length = 2048, blank=True)
    request_method = models.CharField(max_length=7, blank=True, null=True)
    payloads = models.TextField(blank=True)
    headers = models.JSONField(default=dict, blank=True)
    postData = models.TextField(blank=True)
    ComplexPathPython = models.TextField(blank=True)
    ComplexAttackPython = models.FileField(upload_to=user_directory_path, blank=True)
    path = fields.ArrayField(models.CharField(max_length = 2048), blank=True )
    creds = fields.ArrayField(models.CharField(max_length = 256), blank=True)
    pathDeveloper = models.TextField(blank=True)
    rawRequest = fields.ArrayField(models.CharField(max_length=10240), blank=True)
    SSL = models.BooleanField(default='False')
    timeout_betweenRequest = models.CharField(max_length=10, blank=True)
    repeatnumb = models.CharField(max_length=6, blank=True)
    redirect = models.BooleanField(default='False')
    matchers_status = ArrayField(models.CharField(max_length=2048), blank=True)
    matchers_headers = ArrayField(models.CharField(max_length=2048), blank=True)
    matchers_bodys = ArrayField(models.CharField(max_length=2048), blank=True)
    matchers_words = ArrayField(models.CharField(max_length=2048), blank=True)
    shodan_query = ArrayField(models.CharField(max_length=2048), blank=True)
    google_dork = models.TextField(blank=True, null=True)
    tags = fields.ArrayField(models.CharField(max_length=75))
    tcpversioning = models.CharField(max_length = 2048, blank=True)
    

