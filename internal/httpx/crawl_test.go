package httpx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCrawlHonoursDepthPerPage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/html")
		switch request.URL.Path {
		case "/":
			_, _ = writer.Write([]byte(`<a href="/level1">one</a>`))
		case "/level1":
			_, _ = writer.Write([]byte(`<a href="/level2">two</a>`))
		default:
			_, _ = writer.Write([]byte("leaf"))
		}
	}))
	defer server.Close()

	results := New(time.Second, "test").Crawl(context.Background(), server.URL, "127.0.0.1", 2, 10, 2, nil)
	var paths []string
	for _, result := range results {
		if result.Error == "" {
			paths = append(paths, result.URL)
		}
	}
	joined := strings.Join(paths, " ")
	if strings.Contains(joined, "/level2") || !strings.Contains(joined, "/level1") {
		t.Fatalf("crawl results = %#v", paths)
	}
}
