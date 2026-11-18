// Package report serializes reconx's schema-stable report formats.
package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vrma8/reconx/internal/model"
)

func JSON(path string, value model.Report) error {
	content, err := json.MarshalIndent(value, "", "  ")
	if err != nil { return err }
	return write(path, append(content, '\n'))
}

func CSV(path string, findings []model.Finding) error {
	buffer := bytes.Buffer{}
	writer := csv.NewWriter(&buffer)
	if err := writer.Write([]string{"id", "severity", "title", "asset", "url", "evidence", "mitre", "remediation", "confidence", "source"}); err != nil { return err }
	for _, finding := range findings {
		if err := writer.Write([]string{finding.ID, string(finding.Severity), finding.Title, finding.Asset, finding.URL, finding.Evidence, strings.Join(finding.MITRE, ";"), finding.Remediation, finding.Confidence, finding.Source}); err != nil { return err }
	}
	writer.Flush()
	if err := writer.Error(); err != nil { return err }
	return write(path, buffer.Bytes())
}

func HTML(path string, value model.Report) error {
	const page = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>reconx report – {{.Target.Input}}</title><style>
:root{color-scheme:dark}body{font-family:ui-sans-serif,system-ui,sans-serif;background:#10141d;color:#e7ebf2;margin:0;line-height:1.45}main{max-width:1200px;margin:auto;padding:32px}h1,h2{color:#fff}.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}.card{background:#1b2330;border:1px solid #2d3b50;padding:16px;border-radius:8px}.score{font-size:2rem;font-weight:700}.critical,.high{color:#ff7b7b}.medium{color:#ffd166}.low{color:#9ad1ff}.info{color:#9ec5b8}table{border-collapse:collapse;width:100%;background:#18212e}th,td{border:1px solid #314157;text-align:left;padding:9px;vertical-align:top}th{background:#243146}code{white-space:pre-wrap;word-break:break-word}.muted{color:#aebbd0}</style></head><body><main>
<h1>reconx security assessment</h1><p class="muted">Authorized reconnaissance report · schema {{.SchemaVersion}}</p>
<div class="summary"><div class="card"><b>Target</b><br>{{.Target.Input}}</div><div class="card"><b>Risk</b><br><span class="score {{.Risk.Level}}">{{.Risk.Level}} · {{.Risk.Score}}/100</span></div><div class="card"><b>Findings</b><br>{{.Risk.TotalFindings}}</div><div class="card"><b>Hosts</b><br>{{len .Hosts}}</div></div>
<h2>Findings</h2><table><thead><tr><th>ID</th><th>Severity</th><th>Finding</th><th>Asset / Evidence</th><th>Remediation</th></tr></thead><tbody>{{range .Findings}}<tr><td>{{.ID}}</td><td class="{{.Severity}}">{{.Severity}}</td><td><b>{{.Title}}</b><br>{{.Description}}</td><td>{{.Asset}}<br><code>{{.Evidence}}</code></td><td>{{.Remediation}}</td></tr>{{else}}<tr><td colspan="5">No findings were generated.</td></tr>{{end}}</tbody></table>
<h2>Hosts</h2><table><thead><tr><th>IP</th><th>Names</th><th>Open TCP ports</th><th>Services</th></tr></thead><tbody>{{range .Hosts}}<tr><td>{{.IP}}</td><td>{{join .Names ", "}}</td><td>{{joinInts .OpenTCP ", "}}</td><td>{{range .Services}}{{.Port}}/{{.Name}} {{.Banner}}<br>{{end}}</td></tr>{{end}}</tbody></table>
<h2>Run warnings</h2><ul>{{range .Warnings}}<li>{{.}}</li>{{else}}<li>None</li>{{end}}</ul></main></body></html>`
	functions := template.FuncMap{"join": strings.Join, "joinInts": func(values []int, separator string) string { output:=make([]string,len(values)); for i,value:=range values { output[i]=fmt.Sprint(value) }; return strings.Join(output,separator) }}
	parsed, err := template.New("report").Funcs(functions).Parse(page)
	if err != nil { return err }
	buffer := bytes.Buffer{}
	if err = parsed.Execute(&buffer, value); err != nil { return err }
	return write(path, buffer.Bytes())
}

func PDF(pdfPath, htmlPath string) error {
	tool, err := exec.LookPath("wkhtmltopdf")
	if err != nil { return fmt.Errorf("wkhtmltopdf is not installed; HTML report remains available") }
	command := exec.Command(tool, "--quiet", htmlPath, pdfPath)
	if output, err := command.CombinedOutput(); err != nil { return fmt.Errorf("wkhtmltopdf: %w: %s", err, strings.TrimSpace(string(output))) }
	return nil
}

type DiffResult struct {
	NewSubdomains []string `json:"new_subdomains,omitempty"`
	NewPorts      []string `json:"new_ports,omitempty"`
	NewFindings   []string `json:"new_findings,omitempty"`
}

func Diff(previous, current model.Report) DiffResult {
	oldNames, oldPorts, oldFindings := map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}
	for _, host := range previous.Hosts {
		for _, name := range host.Names { oldNames[name] = struct{}{} }
		for _, port := range host.OpenTCP { oldPorts[fmt.Sprintf("%s:%d", host.IP, port)] = struct{}{} }
	}
	for _, finding := range previous.Findings { oldFindings[finding.ID] = struct{}{} }
	result := DiffResult{}
	for _, host := range current.Hosts {
		for _, name := range host.Names { if _, found := oldNames[name]; !found { result.NewSubdomains = append(result.NewSubdomains, name) } }
		for _, port := range host.OpenTCP { key:=fmt.Sprintf("%s:%d",host.IP,port); if _,found:=oldPorts[key]; !found { result.NewPorts=append(result.NewPorts,key) } }
	}
	for _, finding := range current.Findings { if _, found := oldFindings[finding.ID]; !found { result.NewFindings=append(result.NewFindings, finding.ID+": "+finding.Title) } }
	sort.Strings(result.NewSubdomains); sort.Strings(result.NewPorts); sort.Strings(result.NewFindings)
	return result
}

func Load(path string) (model.Report, error) {
	if info, err := os.Stat(path); err == nil && info.IsDir() { path = filepath.Join(path, "09_report", "report.json") }
	content, err := os.ReadFile(path)
	if err != nil { return model.Report{}, err }
	var value model.Report
	if err = json.Unmarshal(content, &value); err != nil { return model.Report{}, err }
	return value, nil
}

func write(path string, content []byte) error {
	if path == "" { return nil }
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil { return err }
	return os.WriteFile(path, content, 0o600)
}
