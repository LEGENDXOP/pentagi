package notifications

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"strings"

	"pentagi/pkg/docker"
)

// ReadContainerFile reads a single file from a flow's terminal container.
// Returns empty string and nil error if the file doesn't exist or the container is not available.
// This is designed to be safe for fire-and-forget usage — it never panics.
func ReadContainerFile(ctx context.Context, dc docker.DockerClient, containerName string, path string) (string, error) {
	if dc == nil {
		return "", fmt.Errorf("docker client is nil")
	}

	reader, _, err := dc.CopyFromContainer(ctx, containerName, path)
	if err != nil {
		return "", fmt.Errorf("failed to copy from container: %w", err)
	}
	defer reader.Close()

	tarReader := tar.NewReader(reader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("failed to read tar header: %w", err)
		}

		if header.FileInfo().IsDir() {
			continue
		}

		// Limit to 64KB to prevent memory issues
		const maxFileSize int64 = 64 * 1024
		readSize := header.Size
		if readSize > maxFileSize {
			readSize = maxFileSize
		}
		if readSize < 0 {
			continue
		}

		var buf strings.Builder
		limitedReader := io.LimitReader(tarReader, readSize)
		if _, err := io.Copy(&buf, limitedReader); err != nil {
			return "", fmt.Errorf("failed to read file content: %w", err)
		}
		return buf.String(), nil
	}

	return "", nil
}
