package greyproxy

// Config holds configuration for the embedded proxy API service.
type Config struct {
	Addr          string              `yaml:"addr" json:"addr"`
	PathPrefix    string              `yaml:"pathPrefix" json:"pathPrefix"`
	DB            string              `yaml:"db" json:"db"`
	Auther        string              `yaml:"auther" json:"auther"`
	Admission     string              `yaml:"admission" json:"admission"`
	Bypass        string              `yaml:"bypass" json:"bypass"`
	Resolver      string              `yaml:"resolver" json:"resolver"`
	Notifications NotificationsConfig `yaml:"notifications" json:"notifications"`
}

// NotificationsConfig controls OS desktop notifications for pending requests.
type NotificationsConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
}
