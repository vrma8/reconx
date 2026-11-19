// Package report serializes reconx's schema-stable report formats.
package report

import (
	"bytes"
	"encoding/base64"
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
	if err != nil {
		return err
	}
	return write(path, append(content, '\n'))
}

func CSV(path string, findings []model.Finding) error {
	buffer := bytes.Buffer{}
	writer := csv.NewWriter(&buffer)
	if err := writer.Write([]string{"id", "severity", "title", "asset", "url", "evidence", "mitre", "remediation", "confidence", "source", "exploitability", "business_impact"}); err != nil {
		return err
	}
	for _, finding := range findings {
		if err := writer.Write([]string{finding.ID, string(finding.Severity), finding.Title, finding.Asset, finding.URL, finding.Evidence, strings.Join(finding.MITRE, ";"), finding.Remediation, finding.Confidence, finding.Source, finding.Exploitability, finding.BusinessImpact}); err != nil {
			return err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return err
	}
	return write(path, buffer.Bytes())
}

type embeddedScreenshot struct {
	URL string
	Src template.URL
}

// embedScreenshots inlines a bounded number of captured PNGs so the HTML
// report remains self-contained. Missing or oversized files are skipped.
func embedScreenshots(value model.Report) []embeddedScreenshot {
	output := make([]embeddedScreenshot, 0)
	for _, reference := range value.Screenshots {
		if len(output) >= 12 || reference.Path == "" {
			break
		}
		content, err := os.ReadFile(reference.Path)
		if err != nil || len(content) > 2<<20 {
			continue
		}
		mime := "image/png"
		if strings.EqualFold(filepath.Ext(reference.Path), ".jpg") || strings.EqualFold(filepath.Ext(reference.Path), ".jpeg") {
			mime = "image/jpeg"
		}
		uri := "data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(content)
		output = append(output, embeddedScreenshot{URL: reference.URL, Src: template.URL(uri)})
	}
	return output
}

func HTML(path string, value model.Report) error {
	const page = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>reconx report – {{.Target.Input}}</title><style>
:root{color-scheme:dark}body{font-family:ui-sans-serif,system-ui,sans-serif;background:#10141d;color:#e7ebf2;margin:0;line-height:1.45}main{max-width:1200px;margin:auto;padding:32px}h1,h2{color:#fff}.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}.card{background:#1b2330;border:1px solid #2d3b50;padding:16px;border-radius:8px}.score{font-size:2rem;font-weight:700}.critical,.high{color:#ff7b7b}.medium{color:#ffd166}.low{color:#9ad1ff}.info{color:#9ec5b8}table{border-collapse:collapse;width:100%;background:#18212e}th,td{border:1px solid #314157;text-align:left;padding:9px;vertical-align:top}th{background:#243146}code{white-space:pre-wrap;word-break:break-word}.muted{color:#aebbd0}details{background:#18212e;border:1px solid #314157;border-radius:6px;margin:8px 0;padding:8px 12px}summary{cursor:pointer;font-weight:600}input[type=search]{background:#0d121b;color:#e7ebf2;border:1px solid #40536f;border-radius:6px;padding:8px;width:min(420px,100%)}button{background:#243146;color:#e7ebf2;border:1px solid #40536f;border-radius:6px;padding:8px;cursor:pointer}.screenshots{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}.screenshots img{width:100%;border:1px solid #314157;border-radius:6px}
</style></head><body><main>
<h1>reconx security assessment</h1><p class="muted">Authorized reconnaissance report · schema {{.SchemaVersion}} · generated {{.GeneratedAt.Format "2006-01-02T15:04:05Z07:00"}}</p>
<div class="summary"><div class="card"><b>Target</b><br>{{.Target.Input}}</div><div class="card"><b>Risk</b><br><span class="score {{.Risk.Level}}">{{.Risk.Level}} · {{.Risk.Score}}/100</span></div><div class="card"><b>Findings</b><br>{{.Risk.TotalFindings}}</div><div class="card"><b>Hosts</b><br>{{len .Hosts}}</div><div class="card"><b>Requests</b><br>{{.Stats.HTTPRequests}}</div><div class="card"><b>Probes</b><br>{{.Stats.Probes}}</div></div>
<p><input id="findingFilter" type="search" placeholder="Filter findings by severity, asset, title, or evidence" oninput="filterFindings()"> <button type="button" onclick="toggleAll()">Expand / collapse all</button></p>
<details open><summary>Findings</summary><table id="findings"><thead><tr><th>ID</th><th>Severity</th><th>Finding</th><th>Asset / Evidence</th><th>Remediation</th></tr></thead><tbody>{{range .Findings}}<tr data-search="{{.ID}} {{.Severity}} {{.Title}} {{.Asset}} {{.Evidence}}"><td>{{.ID}}</td><td class="{{.Severity}}">{{.Severity}}</td><td><details><summary>{{.Title}}</summary><div><p>{{.Description}}</p><p class="muted">Confidence: {{.Confidence}} · Exploitability: {{.Exploitability}} · Business impact: {{.BusinessImpact}} · MITRE: {{join .MITRE ", "}}</p></div></details></td><td>{{.Asset}}<br><code>{{.Evidence}}</code></td><td>{{.Remediation}}</td></tr>{{else}}<tr><td colspan="5">No findings were generated.</td></tr>{{end}}</tbody></table></details>
<details><summary>Hosts ({{len .Hosts}})</summary><table><thead><tr><th>IP</th><th>Names</th><th>Open ports</th><th>Services</th><th>Network</th></tr></thead><tbody>{{range .Hosts}}<tr><td>{{.IP}}</td><td>{{join .Names ", "}}</td><td>{{joinInts .OpenTCP ", "}}</td><td>{{range .Services}}{{.Port}}/{{.Name}} {{.Banner}}<br>{{end}}</td><td>{{.ASN}} {{.Org}} {{.Country}}</td></tr>{{end}}</tbody></table></details>
<details><summary>Screenshots</summary>{{if .Screenshots}}<div class="screenshots">{{range .Screenshots}}<figure><img src="{{safeURL .Src}}" alt="screenshot"><figcaption class="muted">{{.URL}}</figcaption></figure>{{end}}</div>{{else}}<p class="muted">No screenshots were captured.</p>{{end}}</details>
<details><summary>Phases</summary><ul>{{range .Phases}}<li>[{{.Number}}] {{.Name}} — {{.Status}} ({{.Duration}})</li>{{end}}</ul></details>
<details><summary>Run warnings</summary><ul>{{range .Warnings}}<li>{{.}}</li>{{else}}<li>None</li>{{end}}</ul></details>
<script>function filterFindings(){var q=document.getElementById('findingFilter').value.toLowerCase();var rows=document.querySelectorAll('#findings tr[data-search]');for(var i=0;i<rows.length;i++){rows[i].style.display=rows[i].getAttribute('data-search').toLowerCase().indexOf(q)>=0?'':'none';}}function toggleAll(){var ds=document.querySelectorAll('details');var open=false;for(var i=0;i<ds.length;i++){if(!ds[i].open){open=true;break;}}for(var j=0;j<ds.length;j++){ds[j].open=open;}}</script>
</main></body></html>`
	functions := template.FuncMap{
		"join": strings.Join,
		"joinInts": func(values []int, separator string) string {
			output := make([]string, len(values))
			for i, value := range values {
				output[i] = fmt.Sprint(value)
			}
			return strings.Join(output, separator)
		},
		"safeURL": func(value template.URL) template.URL { return value },
	}
	parsed, err := template.New("report").Funcs(functions).Parse(page)
	if err != nil {
		return err
	}
	buffer := bytes.Buffer{}
	data := struct {
		model.Report
		Screenshots []embeddedScreenshot
	}{Report: value, Screenshots: embedScreenshots(value)}
	if err = parsed.Execute(&buffer, data); err != nil {
		return err
	}
	return write(path, buffer.Bytes())
}

func PDF(pdfPath, htmlPath string) error {
	tool, err := exec.LookPath("wkhtmltopdf")
	if err != nil {
		return fmt.Errorf("wkhtmltopdf is not installed; HTML report remains available")
	}
	command := exec.Command(tool, "--quiet", htmlPath, pdfPath)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("wkhtmltopdf: %w: %s", err, strings.TrimSpace(string(output)))
	}
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
		for _, name := range host.Names {
			oldNames[name] = struct{}{}
		}
		for _, port := range host.OpenTCP {
			oldPorts[fmt.Sprintf("%s:%d", host.IP, port)] = struct{}{}
		}
	}
	for _, finding := range previous.Findings {
		oldFindings[finding.ID] = struct{}{}
	}
	result := DiffResult{}
	for _, host := range current.Hosts {
		for _, name := range host.Names {
			if _, found := oldNames[name]; !found {
				result.NewSubdomains = append(result.NewSubdomains, name)
			}
		}
		for _, port := range host.OpenTCP {
			key := fmt.Sprintf("%s:%d", host.IP, port)
			if _, found := oldPorts[key]; !found {
				result.NewPorts = append(result.NewPorts, key)
			}
		}
	}
	for _, finding := range current.Findings {
		if _, found := oldFindings[finding.ID]; !found {
			result.NewFindings = append(result.NewFindings, finding.ID+": "+finding.Title)
		}
	}
	sort.Strings(result.NewSubdomains)
	sort.Strings(result.NewPorts)
	sort.Strings(result.NewFindings)
	return result
}

func Load(path string) (model.Report, error) {
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		path = filepath.Join(path, "09_report", "report.json")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return model.Report{}, err
	}
	var value model.Report
	if err = json.Unmarshal(content, &value); err != nil {
		return model.Report{}, err
	}
	return value, nil
}

func write(path string, content []byte) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return os.WriteFile(path, content, 0o600)
}
