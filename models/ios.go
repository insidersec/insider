package models

// IOSInfo holds information about iOS apps
type IOSInfo struct {
	SastID             string `json:"sast"`
	BinaryID           string `json:"binId"`
	BinaryType         string `json:"binType"`
	AppName            string `json:"binName"`
	TargetVersion      string `json:"sdk"`
	MinimumOSVersion   string `json:"min"`
	SupportedPlatforms string `json:"pltfm"`
	Build              string `json:"build"`
	Size               string `json:"size"`
	NumberOfLines      int    `json:"numberOfLines"`
}

// IOSPermission holds iOS permissions data
type IOSPermission struct {
	SastID      string `json:"sast"`
	Name        string `json:"permission"`
	Reason      string `json:"reason"`
	Description string `json:"description"`
}

// IOSReport is the representation of the iOS report
type IOSReport struct {
	IOSInfo         IOSInfo         `json:"ios"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Libraries       []Library       `json:"libraries"`
	Permissions     []IOSPermission `json:"permissions"`
}