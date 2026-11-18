package external

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/vrma8/reconx/internal/scanner"
)

// ParseMasscanList parses the stable `-oL` list format. Only syntactically
// valid open TCP records are accepted; comments and unknown lines are ignored.
func ParseMasscanList(reader io.Reader) ([]scanner.Result, error) {
	scannerReader := bufio.NewScanner(reader)
	output := make([]scanner.Result, 0)
	line := 0
	for scannerReader.Scan() {
		line++
		fields := strings.Fields(scannerReader.Text())
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") { continue }
		if len(fields) < 4 || fields[0] != "open" || fields[1] != "tcp" { continue }
		port, err := strconv.Atoi(fields[2])
		if err != nil || port < 1 || port > 65535 { return nil, fmt.Errorf("masscan line %d: invalid port", line) }
		address, err := netip.ParseAddr(fields[3])
		if err != nil { return nil, fmt.Errorf("masscan line %d: invalid address", line) }
		output = append(output, scanner.Result{Host: address.String(), Port: port})
	}
	if err := scannerReader.Err(); err != nil { return nil, err }
	sort.Slice(output, func(i, j int) bool { if output[i].Host == output[j].Host { return output[i].Port < output[j].Port }; return output[i].Host < output[j].Host })
	return dedupeMasscan(output), nil
}

func dedupeMasscan(values []scanner.Result) []scanner.Result {
	if len(values) < 2 { return values }
	output := values[:1]
	for _, value := range values[1:] { last:=output[len(output)-1]; if value.Host != last.Host || value.Port != last.Port { output=append(output,value) } }
	return output
}
