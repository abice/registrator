package route53

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
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

	// route53 zone ID
	zoneId := uri.Host

	if zoneId == "" {
		log.Fatal("must provide zoneId. e.g. route53://zoneId")
	}
	log.Printf("Route53: ZoneID %s\n", zoneId)

	return &Route53Registry{client: r53.New(session.New()),
		path:            uri.Path,
		useEc2Meatadata: useEc2Meatadata,
		zoneId:          zoneId,
		dnsPrefix:       dnsPrefix,
	}
}

type Route53Registry struct {
	client          route53iface.Route53API
	path            string
	useEc2Meatadata bool
	zoneId          string
	dnsSuffix       string
	dnsPrefix       string
	hostname        string
}

// Ping gets the hosted zone name. This name will be used
// as a suffix to all DNS name entries
func (r *Route53Registry) Ping() error {
	params := &r53.GetHostedZoneInput{
		Id: aws.String(r.zoneId),
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
	params := &r53.ListResourceRecordSetsInput{
		HostedZoneId:    aws.String(r.zoneId),
		StartRecordType: aws.String("SRV"),
		StartRecordName: aws.String(fmt.Sprintf("*.%s", r.dnsSuffix)),
	}

	resp, err := r.client.ListResourceRecordSets(params)
	if err != nil {
		return nil, err
	}

	services := make([]*bridge.Service, 0, len(resp.ResourceRecordSets))
	for _, rrs := range resp.ResourceRecordSets {
		log.Printf("ResourceRecordSets %s", rrs.GoString())

		for _, record := range rrs.ResourceRecords {
			if record.Value == nil {
				log.Println("Route53: Skipping null SRV Record Value")
				continue
			}
			parts := strings.Split(*record.Value, ` `)
			if len(parts) != 4 {
				log.Printf("Route53: Skipping malformed SRV record: %s\n", *record.Value)
				continue
			}
			port, err := strconv.Atoi(parts[2])
			if err != nil {
				log.Println("Route53: Skipping unparseable port")
				continue
			}

			services = append(services, &bridge.Service{
				ID:   fmt.Sprintf("%d_%s", port, parts[3]),
				Name: *rrs.Name,
				Port: port,
				TTL:  (int)(*rrs.TTL),
			})
		}
	}

	return services, err
}

func (r *Route53Registry) Register(service *bridge.Service) error {
	log.Printf("Route53: Registering service %s||%s\n", service.ID, service.Name)

	// query Route53 for existing records
	name := service.Name + "." + r.dnsSuffix

	// determine the hostname
	hostname := r.getHostname()
	r.updateLocalARecord(service, "UPSERT")
	r.updatePublicARecord(service, "UPSERT")

	// append our new record and persist
	var recordSet ResourceRecordSet
	recordSet, err := r.GetServiceEntry(r.zoneId, name)

	if recordSet.nameIs(name) {
		// update existing DNS record
		value := fmt.Sprintf("1 1 %d %s", service.Port, hostname)
		log.Println("Updating DNS entry for", name, "adding values", value)
		// Since MaxItems is set to 1 we'll only ever get a single record
		// get the resource records associated with this name
		var resourceRecords ResourceRecords = recordSet[0].ResourceRecords

		resourceRecords = append(resourceRecords, &r53.ResourceRecord{Value: aws.String(value)})
		r.UpdateDns(r.zoneId, name, "UPSERT", resourceRecords)
	} else {
		// Create new DNS record
		value := fmt.Sprintf("1 1 %d %s", service.Port, hostname)
		log.Println("Creating new DNS Entry for", name, "with value", value)
		resourceRecord := []*r53.ResourceRecord{
			&r53.ResourceRecord{
				Value: aws.String(value),
			},
		}
		r.UpdateDns(r.zoneId, name, "UPSERT", resourceRecord)
	}

	return err
}

func (r *Route53Registry) updateLocalARecord(service *bridge.Service, action string) error {
	name := service.Name + "." + r.dnsSuffix
	result := false
	if pubRecord, ok := service.Attrs[PublishLocalARecord]; ok {
		publishRecord, err := strconv.ParseBool(pubRecord)
		if err == nil {
			result = publishRecord
		}
	}
	if result {
		log.Printf("Route53: Updating LocalARecord %s\n", name)
		err := r.UpdateDnsRecordSet(r.zoneId, name, action, &r53.ResourceRecordSet{ // Required
			Name: aws.String(name), // Required
			Type: aws.String("A"),  // Required
			ResourceRecords: []*r53.ResourceRecord{
				&r53.ResourceRecord{
					Value: aws.String(r.getLocalIPv4()),
				},
			},
			SetIdentifier: aws.String(r.getHostname()),
			TTL:           aws.Int64(TTL),
			Weight:        aws.Int64(1),
		})
		return err
	}
	return nil
}

func (r *Route53Registry) updatePublicARecord(service *bridge.Service, action string) error {
	name := service.Name + "." + r.dnsSuffix
	result := false
	if pubRecord, ok := service.Attrs[PublishPublicARecord]; ok {
		publishRecord, err := strconv.ParseBool(pubRecord)
		if err == nil {
			result = publishRecord
		}
	}
	if result {
		log.Printf("Route53: Updating PublicARecord %s\n", name)
		err := r.UpdateDnsRecordSet(r.zoneId, name, action, &r53.ResourceRecordSet{ // Required
			Name: aws.String(name), // Required
			Type: aws.String("A"),  // Required
			ResourceRecords: []*r53.ResourceRecord{
				&r53.ResourceRecord{
					Value: aws.String(r.getPublicIPv4()),
				},
			},
			SetIdentifier: aws.String(r.getHostname()),
			TTL:           aws.Int64(TTL),
			Weight:        aws.Int64(1),
		})
		return err
	}
	return nil
}

func (r *Route53Registry) Deregister(service *bridge.Service) error {

	// query Route53 for existing records
	name := service.Name + "." + r.dnsSuffix

	// determine the hostname
	hostname := r.getHostname()

	r.updateLocalARecord(service, "DELETE")
	r.updatePublicARecord(service, "DELETE")

	// Query Route 53 for for DNS record
	var recordSet ResourceRecordSet
	recordSet, err := r.GetServiceEntry(r.zoneId, name)
	if err != nil {
		return err
	}

	if recordSet.nameIs(name) {
		// find the position of the value to deregister
		var resourceRecords ResourceRecords = recordSet[0].ResourceRecords
		pos := resourceRecords.pos(hostname)
		// remove record from set
		if pos != -1 {
			if len(resourceRecords) == 1 {
				// delete this DNS record set
				// the only associated value is the one we're removing
				r.UpdateDns(r.zoneId, name, "DELETE", resourceRecords)
			} else {
				// Remove the value referenced in the SRV record, do not remove the DNS entry
				resourceRecords = append(resourceRecords[:pos], resourceRecords[pos+1:]...)
				r.UpdateDns(r.zoneId, name, "UPSERT", resourceRecords)
			}
		}
	} else {
		log.Println("Could not find service", name, "to deregister")
	}

	return err
}

func (r *Route53Registry) Refresh(service *bridge.Service) error {
	return nil
}

// Gets route53 service entry for the provided zoneId and recordName
func (r *Route53Registry) GetServiceEntry(zoneId string, recordName string) ([]*r53.ResourceRecordSet, error) {
	params := &r53.ListResourceRecordSetsInput{
		HostedZoneId:          aws.String(zoneId),
		StartRecordName:       aws.String(recordName),
		StartRecordIdentifier: aws.String(r.getHostname()),
		MaxItems:              aws.String("1"),
	}

	resp, err := r.client.ListResourceRecordSets(params)

	if _, ok := err.(awserr.Error); ok {
		if reqErr, ok := err.(awserr.RequestFailure); ok {
			// a service error occurred
			log.Println(reqErr.Code(), reqErr.Message(), reqErr.StatusCode(), reqErr.RequestID())
		}
	}

	return resp.ResourceRecordSets, err
}

// updates DNS entry for the provided zoneId and record name
func (r *Route53Registry) UpdateDns(zoneId string, recordName string, action string, resourceRecords []*r53.ResourceRecord) error {
	return r.UpdateDnsRecordSet(zoneId, recordName, action, &r53.ResourceRecordSet{ // Required
		Name:            aws.String(recordName), // Required
		Type:            aws.String("SRV"),      // Required
		ResourceRecords: resourceRecords,
		SetIdentifier:   aws.String(r.getHostname()),
		TTL:             aws.Int64(TTL),
		Weight:          aws.Int64(1),
	})
}

// updates DNS entry for the provided zoneId and record name
func (r *Route53Registry) UpdateDnsRecordSet(zoneId string, recordName string, action string, resourceRecordSet *r53.ResourceRecordSet) error {

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
		HostedZoneId: aws.String(zoneId), // Required
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

func (r *Route53Registry) getHostname() string {
	if "" == r.hostname {
		// determine the hostname
		if r.useEc2Meatadata {
			var hnerr error
			r.hostname, hnerr = ec2Meta("hostname")
			if hnerr != nil {
				log.Fatal("Unable to determine EC2 hostname, defaulting to HOSTNAME")
				r.hostname, _ = os.Hostname()
			}
		} else {
			var hnerr error
			r.hostname, hnerr = os.Hostname()
			if hnerr != nil {
				log.Fatal("Can't get host name", hnerr)
			}
		}
	}
	return r.hostname
}

// Uses ec2 metadata service
// see http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
func ec2Meta(key string) (string, error) {
	resp, err := http.Get("http://169.254.169.254/latest/meta-data/" + key)
	if err != nil {
		log.Fatal("Error getting meta-data ", err)
	}

	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)

	return string(data[:]), err
}

func (r *Route53Registry) getLocalIPv4() string {
	var ipv4 string
	// determine the hostname
	if r.useEc2Meatadata {
		var hnerr error
		ipv4, hnerr = ec2Meta("local-ipv4")
		if hnerr != nil {
			log.Fatal("Unable to determine EC2 hostname, defaulting to HOSTNAME")
			ipv4, _ = externalIP()
		}
	} else {
		var hnerr error
		ipv4, hnerr = externalIP()
		if hnerr != nil {
			log.Fatal("Can't get host name", hnerr)
		}
	}
	return ipv4
}

func (r *Route53Registry) getPublicIPv4() string {
	var ipv4 string
	// determine the hostname
	if r.useEc2Meatadata {
		var hnerr error
		ipv4, hnerr = ec2Meta("public-ipv4")
		if hnerr != nil {
			log.Fatal("Unable to determine EC2 public ipv4, defaulting to internal lookup")
			ipv4, _ = externalIP()
		}
	} else {
		var hnerr error
		ipv4, hnerr = externalIP()
		if hnerr != nil {
			log.Fatal("Can't get IPv4", hnerr)
		}
	}
	return ipv4
}

func externalIP() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return "", err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue // not an ipv4 address
			}
			return ip.String(), nil
		}
	}
	return "", errors.New("are you connected to the network?")
}
