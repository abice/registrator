package route53

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
)

func (r *Route53Registry) getTxtDomain() string {
	return fmt.Sprintf("%s.services.%s", r.getLocalHostname(), r.dnsSuffix)
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

func (r *Route53Registry) getLocalHostname() string {

	hostname, hnerr := os.Hostname()
	if hnerr != nil {
		log.Println("Can't get host name", hnerr)
	}
	return hostname
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
