// Package cloud builds bounded, provider-specific public asset checks.
package cloud

import (
	"net/url"
	"sort"
	"strings"
)

type Candidate struct {
	Provider string `json:"provider"`
	Name     string `json:"name"`
	URL      string `json:"url"`
}

type Result struct {
	Candidate
	StatusCode int    `json:"status_code,omitempty"`
	Status     string `json:"status"`
	Error      string `json:"error,omitempty"`
}

var bucketSuffixes = []string{"assets", "backup", "data", "dev", "prod", "staging", "static"}

// Candidates creates provider-valid names from discovered in-scope DNS names.
// It uses only reversible, target-derived label permutations; it never lists
// buckets or generates unrelated dictionary names. maximum caps the total
// outbound object-store probes a caller can make.
func Candidates(names []string, maximum int) []Candidate {
	if maximum < 1 {
		return nil
	}
	bases := bucketNames(names)
	output := make([]Candidate, 0, min(len(bases)*4, maximum))
	seen := make(map[string]struct{})
	add := func(candidate Candidate) bool {
		if _, found := seen[candidate.URL]; found {
			return false
		}
		seen[candidate.URL] = struct{}{}
		output = append(output, candidate)
		return len(output) == maximum
	}
	for _, name := range bases {
		if validBucketName(name) {
			if add(Candidate{Provider: "AWS S3", Name: name, URL: "https://" + name + ".s3.amazonaws.com/"}) {
				return output
			}
		}
		if azure := strings.ReplaceAll(name, "-", ""); validAzureAccountName(azure) {
			if add(Candidate{Provider: "Azure Blob", Name: azure, URL: "https://" + azure + ".blob.core.windows.net/"}) {
				return output
			}
		}
		if validBucketName(name) {
			if add(Candidate{Provider: "Google Cloud Storage", Name: name, URL: "https://" + url.PathEscape(name) + ".storage.googleapis.com/"}) {
				return output
			}
			if add(Candidate{Provider: "DigitalOcean Spaces", Name: name, URL: "https://" + name + ".digitaloceanspaces.com/"}) {
				return output
			}
		}
	}
	return output
}

// Classify turns a body-free object-store probe into conservative status. A
// 200 response means the root was readable/listable, whereas access denials
// only establish that a provider endpoint appears to exist and must be
// manually reviewed.
// NeedsGETFallback reports when an object-store endpoint explicitly rejects
// HEAD. A bounded GET then gives Phase 2 a read-only second chance without
// downloading objects or treating a HEAD-only response as a false negative.
func NeedsGETFallback(statusCode int, probeError string) bool {
	return probeError == "" && (statusCode == 405 || statusCode == 501)
}

func Classify(candidate Candidate, statusCode int, probeError string) Result {
	result := Result{Candidate: candidate, StatusCode: statusCode, Error: probeError}
	if probeError != "" {
		result.Status = "error"
		return result
	}
	if statusCode == 404 {
		result.Status = "not_found"
		return result
	}
	if statusCode == 200 {
		result.Status = "publicly_readable_or_listable"
		return result
	}
	if existsOrRestricted(candidate.Provider, statusCode) {
		result.Status = "exists_or_access_restricted"
		return result
	}
	result.Status = "inconclusive"
	return result
}

func existsOrRestricted(provider string, statusCode int) bool {
	switch provider {
	case "AWS S3":
		return statusCode == 301 || statusCode == 302 || statusCode == 307 || statusCode == 400 || statusCode == 401 || statusCode == 403
	case "Azure Blob":
		// Azure account roots commonly return 400 when the account exists but
		// a container/resource was not specified.
		return statusCode == 400 || statusCode == 401 || statusCode == 403
	case "Google Cloud Storage", "DigitalOcean Spaces":
		return statusCode == 301 || statusCode == 302 || statusCode == 307 || statusCode == 400 || statusCode == 401 || statusCode == 403
	default:
		return false
	}
}

func bucketNames(names []string) []string {
	values := make(map[string]struct{})
	add := func(value string) {
		value = strings.Trim(value, "-")
		if validBucketName(value) {
			values[value] = struct{}{}
		}
	}
	for _, name := range names {
		labels := strings.Split(strings.Trim(strings.ToLower(strings.TrimSpace(name)), "."), ".")
		clean := make([]string, 0, len(labels))
		valid := true
		for _, label := range labels {
			if !validLabel(label) {
				valid = false
				break
			}
			clean = append(clean, label)
		}
		if !valid || len(clean) == 0 {
			continue
		}
		bases := []string{strings.Join(clean, "-")}
		if len(clean) > 1 {
			bases = append(bases, strings.Join(clean[:2], "-"), strings.Join(clean[len(clean)-2:], "-"))
		}
		if len(clean) > 2 {
			bases = append(bases, strings.Join(clean[:len(clean)-1], "-"))
		}
		for _, base := range bases {
			if !validBucketName(base) {
				continue
			}
			add(base)
			for _, suffix := range bucketSuffixes {
				add(base + "-" + suffix)
			}
		}
	}
	output := make([]string, 0, len(values))
	for value := range values {
		output = append(output, value)
	}
	sort.Strings(output)
	return output
}

func validLabel(value string) bool {
	if value == "" || len(value) > 63 || strings.HasPrefix(value, "-") || strings.HasSuffix(value, "-") {
		return false
	}
	for _, character := range value {
		if character != '-' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func validBucketName(value string) bool {
	return len(value) >= 3 && len(value) <= 63 && validLabel(value)
}

func validAzureAccountName(value string) bool {
	if len(value) < 3 || len(value) > 24 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func min(left, right int) int {
	if left < right {
		return left
	}
	return right
}
