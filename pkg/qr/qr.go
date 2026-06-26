package qr

import (
	"fmt"
	"io"

	"github.com/skip2/go-qrcode"
)

// RenderPairingQr generates and returns a highly-dense, compact QR code string
// using Unicode half-height block characters to preserve 1:1 aspect ratio.
func RenderPairingQr(url string) (string, error) {
	qr, err := qrcode.New(url, qrcode.Medium)
	if err != nil {
		return "", err
	}

	// Use ToSmallString (uses Unicode half-height characters: ▀, ▄, █)
	// which renders twice as compact and prevents vertical stretching in terminals.
	return qr.ToSmallString(false), nil
}

// PrintPairingQr prints the connection link and QR code directly to the provided writer
func PrintPairingQr(w io.Writer, url string) {
	qrStr, err := RenderPairingQr(url)
	if err != nil {
		fmt.Fprintf(w, "Failed to render QR Code: %v\n", err)
		return
	}

	fmt.Fprintf(w, "\nConnection Link:\n%s\n", url)
	fmt.Fprintln(w, "\nScan this QR code to connect/pair:")
	fmt.Fprintln(w, qrStr)
}
