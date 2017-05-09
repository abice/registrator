package route53

import (
	"fmt"
	"log"
	"net/url"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	r53 "github.com/aws/aws-sdk-go/service/route53"
	"github.com/aws/aws-sdk-go/service/route53/route53iface"
	"github.com/gliderlabs/registrator/bridge"
)

const EC2MetaDataKey = "useEC2MetadataForHostname"
const DNSPrefix = "dnsPrefix"
const PublishPublicARecord = "publicarecord"
const PublishLocalARecord = "localarecord"
const RecordPerHost = "recordPerHost"
const TTL = 30

func init() {
	bridge.Register(new(Factory), "route53")
}

type Factory struct{}

func (f *Factory) New(uri *url.URL) bridge.RegistryAdapter {
	// use ec2 metadata service
	q := uri.Query()
	log.Printf("Route53: Query %+v", q)

	useEc2Meatadata, err := strconv.ParseBool(q.Get(EC2MetaDataKey))
	if err != nil {
		useEc2Meatadata = false
	}
	log.Printf("Route53: useEc2 %t", useEc2Meatadata)

	dnsPrefix := q.Get(DNSPrefix)
	log.Printf("Route53: dnsPrefix %s", dnsPrefix)

	rph := q.Get(RecordPerHost)
	recordPerHost, err := strconv.ParseBool(rph)
	if err != nil {
		recordPerHost = false
	}
	log.Printf("Route53: recordPerHost %t", recordPerHost)

	// route53 zone ID
	zoneID := uri.Host

	if zoneID == "" {
		log.Fatal("must provide zoneID. e.g. route53://zoneID")
	}
	log.Printf("Route53: ZoneID %s\n", zoneID)

	return &Route53Registry{client: r53.New(session.New()),
		path:            uri.Path,
		useEc2Meatadata: useEc2Meatadata,
		zoneID:          zoneID,
		dnsPrefix:       dnsPrefix,
		recordPerHost:   recordPerHost,
	}
}

type Route53Registry struct {
	client          route53iface.Route53API
	path            string
	useEc2Meatadata bool
	zoneID          string
	dnsSuffix       string
	dnsPrefix       string
	hostname        string
	recordPerHost   bool
	containerLookup map[string]string
}

// Ping gets the hosted zone name. This name will be used
// as a suffix to all DNS name entries
func (r *Route53Registry) Ping() error {
	params := &r53.GetHostedZoneInput{
		Id: aws.String(r.zoneID),
	}
	resp, err := r.client.GetHostedZone(params)
	if err != nil {
		return err
	}
	r.dnsSuffix = *resp.HostedZone.Name

	if "" != r.dnsPrefix {
		r.dnsSuffix = r.dnsPrefix + "." + r.dnsSuffix
	}

	return err
}

func (r *Route53Registry) Services() ([]*bridge.Service, error) {
	hostname := r.getHostname()
	params := &r53.ListResourceRecordSetsInput{
		HostedZoneId:          aws.String(r.zoneID),
		StartRecordType:       aws.String(r53.RRTypeTxt),
		StartRecordName:       aws.String(r.getTxtDomain()),
		StartRecordIdentifier: aws.String(r.getTxtID()),
	}

	resp, err := r.client.ListResourceRecordSets(params)
	if err != nil {
		return nil, err
	}

	services := make([]*bridge.Service, 0, len(resp.ResourceRecordSets))
	for _, rrs := range resp.ResourceRecordSets {
		if r53.RRTypeTxt != *rrs.Type {
			log.Printf("Skipping non TXT record for services")
			continue
		}
		log.Printf("ResourceRecordSets %s", rrs.GoString())

		for _, record := range rrs.ResourceRecords {
			if record.Value == nil {
				log.Println("Route53: Skipping null Record Value")
				continue
			}
			value := strings.TrimSuffix(strings.TrimPrefix(*record.Value, `"`), `"`)
			// ip-10-174-54-189:ecs-fluentd-aggr-7-fluentd-aggr-def08de0ae8ef9977c00:24225
			parts := strings.Split(value, `|`)
			var serviceIDValue string
			if len(parts) < 4 {
				log.Printf("Route53: Not sure if the IPs just didn't get put in, so maybe we'll try for just using the ID")
				serviceIDValue = value
			} else {
				serviceIDValue = parts[0]
			}
			serviceIDparts := strings.Split(serviceIDValue, `:`)
			if len(serviceIDparts) != 3 {
				log.Printf("Route53: Skipping malformed Registrator Service record: %s\n", value)
				continue
			}
			if parts[0] == hostname || parts[0] == r.getLocalHostname() {
				// This is a local service, so we should return it.
				port, err := strconv.Atoi(parts[2])
				if err != nil {
					log.Println("Route53: Skipping unparseable port")
					continue
				}

				services = append(services, &bridge.Service{
					ID:   value,
					Name: parts[3],
					Port: port,
					TTL:  (int)(*rrs.TTL),
				})
			}
		}
	}

	log.Println("Existing Services", services)

	return services, err
}

func (r *Route53Registry) Register(service *bridge.Service) error {
	log.Printf("Route53: Registering service %s||%s\n", service.ID, service.Name)

	// query Route53 for existing records
	name := r.getServiceName(service)

	// determine the hostname
	hostname := r.getHostname()
	r.updateLocalARecord(service, "UPSERT")
	r.updatePublicARecord(service, "UPSERT")

	r.appendToRecordSet(r.getTxtDomain(), r53.RRTypeTxt, r.getTxtValue(service), r.getTxtID())

	err := r.appendToRecordSet(name, r53.RRTypeSrv, fmt.Sprintf("1 1 %d %s", service.Port, hostname), r.getRecordID(name))

	return err
}

func (r *Route53Registry) Deregister(service *bridge.Service) error {
	log.Printf("Route53: Deregistering service %s || %s\n", service.ID, service.Name)

	// query Route53 for existing records
	name := r.getServiceName(service)

	// determine the hostname
	hostname := r.getHostname()

	r.updateLocalARecord(service, "DELETE")
	r.updatePublicARecord(service, "DELETE")
	err := r.removeFromRecordSet(name, r53.RRTypeSrv, fmt.Sprintf("1 1 %d %s", service.Port, hostname), r.getRecordID(name))
	r.removeFromRecordSet(r.getTxtDomain(), r53.RRTypeTxt, r.getTxtValue(service), r.getTxtID())

	return err
}

func (r *Route53Registry) getServiceName(service *bridge.Service) string {
	// return fmt.Sprintf("%s.%s", service.Name, r.dnsSuffix)
	return fmt.Sprintf("_%s._%s.%s", service.Name, "tcp", r.dnsSuffix)
}

func (r *Route53Registry) Refresh(service *bridge.Service) error {
	return nil
}

// GetServiceEntry gets route53 service entry for the provided zoneID and recordName
func (r *Route53Registry) GetServiceEntry(zoneID string, recordName string, recordType string, identifier string) ([]*r53.ResourceRecordSet, error) {
	params := &r53.ListResourceRecordSetsInput{
		HostedZoneId:          aws.String(zoneID),
		StartRecordName:       aws.String(recordName),
		StartRecordIdentifier: aws.String(identifier),
		StartRecordType:       aws.String(recordType),
		MaxItems:              aws.String("1"),
	}

	resp, err := r.client.ListResourceRecordSets(params)

	if _, ok := err.(awserr.Error); ok {
		if reqErr, ok := err.(awserr.RequestFailure); ok {
			// a service error occurred
			log.Println("Route53: Error getting resource record sets:", reqErr.Code(), reqErr.Message(), reqErr.StatusCode(), reqErr.RequestID())
		}
	}

	return resp.ResourceRecordSets, err
}

// UpdateDNS updates DNS entry for the provided zoneID and record name
func (r *Route53Registry) UpdateDNS(zoneID, recordName, action, recordType, identifier string, resourceRecords []*r53.ResourceRecord) error {
	return r.UpdateDNSRecordSet(zoneID, recordName, action, &r53.ResourceRecordSet{ // Required
		Name:            aws.String(recordName), // Required
		Type:            aws.String(recordType), // Required
		ResourceRecords: resourceRecords,
		SetIdentifier:   aws.String(identifier),
		TTL:             aws.Int64(TTL),
		Weight:          aws.Int64(1),
	})
}

// UpdateDNSRecordSet is a generic method for calling the Route53 ChangeResourceRecordSets call
func (r *Route53Registry) UpdateDNSRecordSet(zoneID string, recordName string, action string, resourceRecordSet *r53.ResourceRecordSet) error {

	params := &r53.ChangeResourceRecordSetsInput{
		ChangeBatch: &r53.ChangeBatch{ // Required
			Changes: []*r53.Change{ // Required
				&r53.Change{ // Required
					Action:            aws.String(action), // Required
					ResourceRecordSet: resourceRecordSet,
				},
			},
			Comment: aws.String(fmt.Sprintf("Updated recordset for %s", recordName)),
		},
		HostedZoneId: aws.String(zoneID), // Required
	}
	_, err := r.client.ChangeResourceRecordSets(params)

	if _, ok := err.(awserr.Error); ok {
		// Generic AWS Error with Code, Message, and original error (if any)
		if reqErr, ok := err.(awserr.RequestFailure); ok {
			// A service error occurred
			log.Println(fmt.Println(reqErr.Code(), reqErr.Message(), reqErr.StatusCode(), reqErr.RequestID()))
		}
	}

	return err
}

type ResourceRecords []*r53.ResourceRecord

// find the index of the record that contains the input string
func (slice ResourceRecords) pos(value string) int {
	for i, v := range slice {
		if strings.Contains(*v.Value, value) {
			return i
		}
	}
	return -1
}

type ResourceRecordSet []*r53.ResourceRecordSet

func (slice ResourceRecordSet) nameIs(name string) bool {
	if slice != nil && *slice[0].Name == name {
		return true
	}
	return false
}

func (slice ResourceRecordSet) typeIs(t string) bool {
	if slice != nil && *slice[0].Type == t {
		return true
	}
	return false
}

func (r *Route53Registry) updateLocalARecord(service *bridge.Service, action string) (string, error) {
	name := service.Name + "." + r.dnsSuffix
	result := false
	if pubRecord, ok := service.Attrs[PublishLocalARecord]; ok {
		publishRecord, err := strconv.ParseBool(pubRecord)
		if err == nil {
			result = publishRecord
		}
	}
	var err error
	var ip string
	if result {
		ip = r.getLocalIPv4()
		switch strings.ToUpper(action) {
		case "UPSERT":
			log.Printf("Route53: Appending LocalARecord %s\n", name)
			err = r.appendToRecordSet(name, r53.RRTypeA, ip, r.getRecordID(name))
			break
		case "DELETE":
			log.Printf("Route53: Appending LocalARecord %s\n", name)
			err = r.removeFromRecordSet(name, r53.RRTypeA, ip, r.getRecordID(name))
			break
		default:
			log.Printf("Unknown action: %s", action)
		}
		return ip, err
	}
	return ip, nil
}

func (r *Route53Registry) updatePublicARecord(service *bridge.Service, action string) (string, error) {
	name := service.Name + "." + r.dnsSuffix
	result := false
	if pubRecord, ok := service.Attrs[PublishPublicARecord]; ok {
		publishRecord, err := strconv.ParseBool(pubRecord)
		if err == nil {
			result = publishRecord
		}
	}
	var err error
	var ip string
	if result {
		ip = r.getPublicIPv4()
		switch strings.ToUpper(action) {
		case "UPSERT":
			log.Printf("Route53: Appending PublicARecord %s\n", name)
			err = r.appendToRecordSet(name, r53.RRTypeA, ip, r.getRecordID(name))
			break
		case "DELETE":
			log.Printf("Route53: Appending PublicARecord %s\n", name)
			err = r.removeFromRecordSet(name, r53.RRTypeA, ip, r.getRecordID(name))
			break
		default:
			log.Printf("Unknown action: %s", action)
		}
		return ip, err
	}
	return ip, nil
}

func (r *Route53Registry) appendToRecordSet(name string, recordType string, value string, identifier string) error {
	var recordSet ResourceRecordSet
	recordSet, err := r.GetServiceEntry(r.zoneID, name, recordType, identifier)
	if err != nil {
		return err
	}

	if recordSet.nameIs(name) && recordSet.typeIs(recordType) {
		// update existing DNS record
		log.Println("Updating DNS entry for", recordType, name, "adding values", value)
		// Since MaxItems is set to 1 we'll only ever get a single record
		// get the resource records associated with this name
		var resourceRecords ResourceRecords = recordSet[0].ResourceRecords
		resourceRecords = append(resourceRecords, &r53.ResourceRecord{Value: aws.String(value)})

		err = r.UpdateDNS(r.zoneID, name, "UPSERT", recordType, identifier, resourceRecords)
	} else {
		// Create new DNS record
		log.Println("Creating new DNS Entry for", recordType, name, "with value", value)
		resourceRecord := []*r53.ResourceRecord{
			&r53.ResourceRecord{
				Value: aws.String(value),
			},
		}
		err = r.UpdateDNS(r.zoneID, name, "UPSERT", recordType, identifier, resourceRecord)
	}
	return err
}

func (r *Route53Registry) removeFromRecordSet(name string, recordType string, value string, identifier string) error {
	var recordSet ResourceRecordSet
	recordSet, err := r.GetServiceEntry(r.zoneID, name, recordType, identifier)
	if err != nil {
		return err
	}

	if recordSet.nameIs(name) && recordSet.typeIs(recordType) {
		// find the position of the value to deregister
		var resourceRecords ResourceRecords = recordSet[0].ResourceRecords
		pos := resourceRecords.pos(value)

		// remove record from set
		if pos != -1 {
			if len(resourceRecords) == 1 {
				// delete this DNS record set
				// the only associated value is the one we're removing
				r.UpdateDNS(r.zoneID, name, "DELETE", recordType, identifier, resourceRecords)
			} else {
				// Remove the value referenced in the record, do not remove the DNS entry
				resourceRecords = append(resourceRecords[:pos], resourceRecords[pos+1:]...)
				r.UpdateDNS(r.zoneID, name, "UPSERT", recordType, identifier, resourceRecords)
			}
		} else {
			log.Println("Could not find service", recordType, name, "to deregister")
		}
	}
	return err
}

func (r *Route53Registry) getRecordID(recordName string) string {
	if r.recordPerHost {
		return r.getHostname()
	}

	return recordName
}
