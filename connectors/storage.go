package connectors

import (
	"log"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

const (
	// WallESamplesFolder is the folder to retrive samples to analyze
	WallESamplesFolder = "walle/"
	// Evidences is the folder where E.V.E have to upload finding evidences
	Evidences = "evidences/"
)

// StorageConnector handles the communication with Amazon Simple Storage Service (S3)
type StorageConnector struct {
	accessKey    string
	accessSecret string
	region       string
	bucket       string
}

type customEnvironmentProvider struct {
	accessKey    string
	accessSecret string
}

func newEnvironmentProvider(key, secret, region string) (customEnvironmentProvider customEnvironmentProvider) {
	customEnvironmentProvider.accessKey = key
	customEnvironmentProvider.accessSecret = secret

	return
}

func (m *customEnvironmentProvider) Retrieve() (credentials.Value, error) {
	return credentials.Value{
		AccessKeyID:     m.accessKey,
		SecretAccessKey: m.accessSecret,
	}, nil
}

func (m *customEnvironmentProvider) IsExpired() bool {
	return false
}

// NewStorageConnector initializes a new AWS S3 connection handler
func NewStorageConnector() (storageConnector StorageConnector) {
	storageConnector.accessKey = os.Getenv("aws_key")
	storageConnector.accessSecret = os.Getenv("aws_secret")
	storageConnector.region = os.Getenv("aws_region")
	storageConnector.bucket = os.Getenv("aws_bucket")

	return
}

// RetrieveObjectFromStorage downloads and saves to 'fileToSave' the object with the given 'name'
func (storageConnector *StorageConnector) RetrieveObjectFromStorage(
	name string,
	fileToSave *os.File) (filename string, shouldExtractHashes bool, err error) {
	customProvider := newEnvironmentProvider(
		storageConnector.accessKey,
		storageConnector.accessSecret,
		storageConnector.region,
	)
	credential := credentials.NewCredentials(&customProvider)

	activeSession := session.Must(session.NewSession(&aws.Config{
		Credentials: credential,
		Region:      aws.String(storageConnector.region),
	}))

	remoteFileName := strings.Split(name, "tmp")[1]

	service := s3manager.NewDownloader(activeSession)

	downloadSize, err := service.Download(fileToSave, &s3.GetObjectInput{
		Bucket: aws.String(storageConnector.bucket),
		Key:    aws.String("walle/" + remoteFileName),
	})

	if err != nil {
		return
	}

	log.Printf("Downloaded %.2f MB.\n", float64(downloadSize)/(1024*1024))

	if downloadSize > 500000000 {
		shouldExtractHashes = false
	} else {
		shouldExtractHashes = true
	}

	filename = name

	return
}

// UploadObjectToStorage uploads a new ZIP file to Amazon's S3 service
func (storageConnector *StorageConnector) UploadObjectToStorage(
	fileToUpload, bucketName, objectKey string) error {
	content, err := os.Open(fileToUpload)

	if err != nil {
		return err
	}

	defer content.Close()

	customProvider := newEnvironmentProvider(
		storageConnector.accessKey,
		storageConnector.accessSecret,
		storageConnector.region,
	)

	credential := credentials.NewCredentials(&customProvider)

	activeSession := session.Must(session.NewSession(&aws.Config{
		Credentials: credential,
		Region:      aws.String(storageConnector.region),
	}))

	uploader := s3manager.NewUploader(activeSession)

	resultInfo, err := uploader.Upload(&s3manager.UploadInput{
		Bucket: aws.String(storageConnector.bucket),
		Key:    aws.String(bucketName + objectKey),
		Body:   content,
	})

	if err != nil {
		return err
	}

	log.Printf("Uploaded %s to %s.", fileToUpload, resultInfo.Location)

	return nil
}
