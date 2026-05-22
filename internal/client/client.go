package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
)

const defaultActor = "vault-cli"

type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

func New(baseURL, apiKey string) *Client {
	return &Client{
		baseURL:    baseURL,
		apiKey:     apiKey,
		httpClient: &http.Client{},
	}
}

func (c *Client) newRequest(method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, c.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}
	return req, nil
}

func (c *Client) doJSON(req *http.Request, out any) error {
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error (%d): %s", resp.StatusCode, string(body))
	}

	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (c *Client) Upload(filePath, actor string) (*UploadResponse, error) {
	if actor == "" {
		actor = defaultActor
	}

	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)

	part, err := w.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		return nil, fmt.Errorf("create form file: %w", err)
	}
	if _, err := io.Copy(part, f); err != nil {
		return nil, fmt.Errorf("copy file: %w", err)
	}
	if err := w.WriteField("actor", actor); err != nil {
		return nil, fmt.Errorf("write actor field: %w", err)
	}
	w.Close()

	req, err := http.NewRequest("POST", c.baseURL+"/upload", &buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}

	var resp UploadResponse
	if err := c.doJSON(req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) Download(documentID, outputDir, actor string) (string, error) {
	if actor == "" {
		actor = defaultActor
	}

	req, err := c.newRequest("GET", "/download/"+documentID+"?actor="+actor, nil)
	if err != nil {
		return "", err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("download request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("API error (%d): %s", resp.StatusCode, string(body))
	}

	// Parse filename from Content-Disposition header
	filename := documentID
	if cd := resp.Header.Get("Content-Disposition"); cd != "" {
		_, params, err := mime.ParseMediaType(cd)
		if err == nil && params["filename"] != "" {
			filename = params["filename"]
		}
	}

	outPath := filepath.Join(outputDir, fmt.Sprintf("recup_%s", filename))
	outFile, err := os.Create(outPath)
	if err != nil {
		return "", fmt.Errorf("create output file: %w", err)
	}
	defer outFile.Close()

	if _, err := io.Copy(outFile, resp.Body); err != nil {
		return "", fmt.Errorf("write output: %w", err)
	}

	return outPath, nil
}

func (c *Client) List() ([]Document, error) {
	req, err := c.newRequest("GET", "/list", nil)
	if err != nil {
		return nil, err
	}

	var resp ListResponse
	if err := c.doJSON(req, &resp); err != nil {
		return nil, err
	}
	return resp.Documents, nil
}

func (c *Client) Rotate() (*RotateResponse, error) {
	req, err := c.newRequest("POST", "/rotate", nil)
	if err != nil {
		return nil, err
	}

	var resp RotateResponse
	if err := c.doJSON(req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
