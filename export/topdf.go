package export

import (
	"log"
	"path/filepath"

	"github.com/jung-kurt/gofpdf"
)

//func resolvePath(prefix string, path ...string) string {
//	pathPrefix,_ := os.Getwd()
//
//	fullPath := []string{pathPrefix}
//	fullPath = append(fullPath, prefix)
//	fullPath = append(fullPath, path...)
//
//	return filepath.Join(fullPath...)
//}

func ResolveFilePath(filename string, folder string) string {
	return filepath.Join(folder, filename)
}

func ToPDF(path string, report []byte) error {
	path = ResolveFilePath("report.pdf", path)
	log.Printf("Exporting to PDF %s\n", path)
	return GeneratePdf(path, report)
}

func GeneratePdf(filename string, report []byte) error {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()
	pdf.SetFont("Arial", "B", 10)

	// CellFormat(width, height, text, border, position after, align, fill, link, linkStr)
	pdf.Cell(0, 0, "Hello, world\ntext1")
	pdf.Cell(0, 0, "text1")

	return pdf.OutputFileAndClose(filename)
}
