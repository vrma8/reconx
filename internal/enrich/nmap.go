// Package enrich normalizes optional tool output into reconx's service model.
package enrich

import (
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/vrma8/reconx/internal/model"
)

type nmapRun struct {
	Hosts []nmapHost `xml:"host"`
}

type nmapHost struct {
	Addresses []struct {
		Address string `xml:"addr,attr"`
		Type    string `xml:"addrtype,attr"`
	} `xml:"address"`
	Ports []struct {
		PortID   string `xml:"portid,attr"`
		Protocol string `xml:"protocol,attr"`
		State    struct {
			State string `xml:"state,attr"`
		} `xml:"state"`
		Service struct {
			Name      string `xml:"name,attr"`
			Product   string `xml:"product,attr"`
			Version   string `xml:"version,attr"`
			Extrainfo string `xml:"extrainfo,attr"`
			Method    string `xml:"method,attr"`
		} `xml:"service"`
	} `xml:"ports>port"`
	OSClasses []struct {
		Family   string   `xml:"family,attr"`
		Vendor   string   `xml:"vendor,attr"`
		OSGen    string   `xml:"osgen,attr"`
		Accuracy string   `xml:"accuracy,attr"`
		CPE      []string `xml:"cpe>cpe"`
	} `xml:"os>osclass"`
}

// ParseNmapXML converts an nmap -oX document into services and an OS map keyed
// by IP. Only open ports become services; unknown/malformed fields are skipped.
func ParseNmapXML(reader io.Reader) ([]model.Service, map[string]string, error) {
	var run nmapRun
	if err := xml.NewDecoder(reader).Decode(&run); err != nil {
		return nil, nil, fmt.Errorf("decode nmap XML: %w", err)
	}
	services := make([]model.Service, 0)
	operatingSystems := make(map[string]string)
	for _, host := range run.Hosts {
		address := ""
		for _, candidate := range host.Addresses {
			if candidate.Address == "" {
				continue
			}
			if candidate.Type == "ipv4" || candidate.Type == "ipv6" {
				address = candidate.Address
				break
			}
			if address == "" {
				address = candidate.Address
			}
		}
		for _, port := range host.Ports {
			if address == "" || port.State.State != "open" {
				continue
			}
			number, err := strconv.Atoi(port.PortID)
			if err != nil || number < 1 || number > 65535 {
				continue
			}
			metadata := map[string]string{}
			if port.Service.Product != "" {
				metadata["product"] = port.Service.Product
			}
			if port.Service.Extrainfo != "" {
				metadata["extrainfo"] = port.Service.Extrainfo
			}
			if port.Service.Method != "" {
				metadata["detection_method"] = port.Service.Method
			}
			name := port.Service.Name
			if name == "" {
				name = "unknown"
			}
			services = append(services, model.Service{
				Host: address, Port: number, Transport: strings.ToLower(port.Protocol), Name: name,
				Version: port.Service.Version, Metadata: metadata,
			})
		}
		if address != "" && len(host.OSClasses) > 0 {
			best := host.OSClasses[0]
			description := strings.TrimSpace(strings.Join([]string{best.Vendor, best.Family, best.OSGen}, " "))
			if description != "" {
				operatingSystems[address] = description + " (" + best.Accuracy + "% accuracy)"
			}
		}
	}
	return services, operatingSystems, nil
}
