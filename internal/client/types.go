package client

type Document struct {
	ID               string `json:"id"`
	OriginalFilename string `json:"original_filename"`
	ContentType      string `json:"content_type"`
	SizeBytes        int    `json:"size_bytes"`
	CreatedAt        string `json:"created_at"`
}

type UploadResponse struct {
	DocumentID string `json:"document_id"`
	Filename   string `json:"filename"`
}

type ListResponse struct {
	Documents []Document `json:"documents"`
}

type RotateResponse struct {
	KeyID     string `json:"key_id"`
	RotatedAt string `json:"rotated_at"`
	Message   string `json:"message"`
}
