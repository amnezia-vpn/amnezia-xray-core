package splithttp

import (
	"runtime"
	"testing"

	"github.com/xtls/xray-core/transport/internet"
)

func TestGetDownloadStreamSettingsInheritsStrictBindingFromCachedSettings(t *testing.T) {
	primarySocket := strictSocketForTest(t)
	downloadSocket := &internet.SocketConfig{
		Mark:                 777,
		Interface:            "other-interface",
		TcpKeepAliveInterval: 17,
	}
	cachedDownload := &internet.MemoryStreamConfig{SocketSettings: downloadSocket}
	streamSettings := &internet.MemoryStreamConfig{
		SocketSettings:   primarySocket,
		DownloadSettings: cachedDownload,
	}

	got, err := getDownloadStreamSettings(streamSettings, &internet.StreamConfig{})
	if err != nil {
		t.Fatalf("getDownloadStreamSettings() error = %v", err)
	}
	if got != cachedDownload {
		t.Fatal("getDownloadStreamSettings() replaced the cached download settings")
	}
	if got.SocketSettings == downloadSocket {
		t.Fatal("getDownloadStreamSettings() mutated the original download socket settings")
	}
	if !got.SocketSettings.StrictBinding {
		t.Fatal("download settings did not inherit strictBinding")
	}
	if got.SocketSettings.Mark != primarySocket.Mark {
		t.Fatalf("download mark = %d, want %d", got.SocketSettings.Mark, primarySocket.Mark)
	}
	if got.SocketSettings.Interface != primarySocket.Interface {
		t.Fatalf("download interface = %q, want %q", got.SocketSettings.Interface, primarySocket.Interface)
	}
	if got.SocketSettings.TcpKeepAliveInterval != downloadSocket.TcpKeepAliveInterval {
		t.Fatal("download-specific non-routing socket options were not preserved")
	}

	again, err := getDownloadStreamSettings(streamSettings, &internet.StreamConfig{})
	if err != nil {
		t.Fatalf("second getDownloadStreamSettings() error = %v", err)
	}
	if again.SocketSettings != got.SocketSettings {
		t.Fatal("cached inherited socket settings were replaced on the second call")
	}
}

func strictSocketForTest(t *testing.T) *internet.SocketConfig {
	t.Helper()

	config := &internet.SocketConfig{StrictBinding: true}
	switch runtime.GOOS {
	case "linux", "android", "freebsd":
		config.Mark = 100
	case "darwin", "ios", "windows":
		config.Interface = "test-interface"
	default:
		t.Skipf("strict binding is unsupported on %s", runtime.GOOS)
	}
	return config
}
