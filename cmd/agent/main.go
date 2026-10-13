package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/Yesveer/wxt-agent/internal/agent"
	"github.com/Yesveer/wxt-agent/internal/config"
	"github.com/Yesveer/wxt-agent/internal/remotecontrol/helperbin"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/yaml.v3"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "wxt-agent",
		Short: "Vsay Agent - Remote terminal access for Linux machines",
		Long:  `Lightweight agent that enables secure remote terminal access to Linux machines`,
	}

	// Version command
	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("wxt-agent %s (commit: %s, built: %s)\n", version, commit, date)
			// Whether the session helper is bundled decides whether remote
			// control works at all, and it is otherwise invisible — a build
			// missing it looks identical until someone tries to connect.
			if helperbin.Available() {
				fmt.Printf("session helper: bundled (%.1f MB)\n", float64(helperbin.Size())/(1<<20))
			} else {
				fmt.Println("session helper: NOT bundled — remote control needs one next to this binary")
			}
		},
	})

	// Configure command
	configureCmd := &cobra.Command{
		Use:   "configure",
		Short: "Configure the agent",
		RunE:  runConfigure,
	}
	configureCmd.Flags().String("token", "", "Agent token")
	configureCmd.Flags().String("tenant", "", "Tenant ID/name")
	configureCmd.Flags().String("org", "", "Organization ID/name")
	configureCmd.Flags().String("project", "", "Project ID/name")
	configureCmd.Flags().String("user", "", "Portal user email")
	configureCmd.Flags().String("linux-user", "", "Linux username")
	configureCmd.Flags().String("host", "", "Backend server host")
	configureCmd.Flags().String("api-host", "", "gRPC server address (IP:PORT, e.g., 192.168.1.6:8081)")
	configureCmd.Flags().String("name", "", "Machine name (display name for this machine)")
	configureCmd.Flags().Bool("allow-sudo", false, "Allow sudo command execution (requires user in sudo group)")
	// EPM: RDP account provisioning removed — remote control joins the user's
	// existing session, so there is no separate RDP account to create.
	// configureCmd.Flags().String("windows-user", "", "Windows username to create/use for RDP (Windows only)")
	// configureCmd.Flags().String("windows-password", "", "Password for the Windows RDP user (Windows only)")
	configureCmd.Flags().Bool("interactive", false, "Interactive configuration")
	configureCmd.Flags().String("tunnel-url", "", "vsay-tunnel server URL (e.g. http://192.168.1.20:8083); enables tunneling when set")
	configureCmd.Flags().StringArray("host-entry", []string{}, "Custom /etc/hosts entry in IP:DOMAIN format (e.g. 192.168.1.5:db.internal); may be repeated up to 5 times")
	rootCmd.AddCommand(configureCmd)

	// Start command
	startCmd := &cobra.Command{
		Use:   "start",
		Short: "Start the agent",
		RunE:  runStart,
	}
	startCmd.Flags().String("config", "/etc/vsay/agent.yaml", "Config file path")
	rootCmd.AddCommand(startCmd)

	// Validate command
	rootCmd.AddCommand(&cobra.Command{
		Use:   "validate",
		Short: "Validate configuration",
		RunE:  runValidate,
	})

	// Show-config command — decrypt and print agent.yaml in readable YAML
	showConfigCmd := &cobra.Command{
		Use:   "show-config",
		Short: "Decrypt and print the agent configuration (requires root)",
		RunE:  runShowConfig,
	}
	showConfigCmd.Flags().String("config", "/etc/vsay/agent.yaml", "Config file path")
	rootCmd.AddCommand(showConfigCmd)

	// Uninstall. Also what Windows Control Panel runs, and what the macOS
	// uninstaller bundle calls, so there is one description of what
	// "installed" means rather than three that drift.
	rootCmd.AddCommand(newUninstallCommand())

	// Permission diagnostics: the only way to tell "the grant is missing" from
	// "the grant exists but does not apply to this build", which look
	// identical from System Settings.
	rootCmd.AddCommand(newCheckPermissionsCommand())

	// Used by the macOS application to ask for the enrolment command in a real
	// text area; AppleScript's dialog only offers a single line.
	rootCmd.AddCommand(newPromptCommand())

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func runConfigure(cmd *cobra.Command, args []string) error {
	// Get flags
	token, _ := cmd.Flags().GetString("token")
	tenant, _ := cmd.Flags().GetString("tenant")
	org, _ := cmd.Flags().GetString("org")
	project, _ := cmd.Flags().GetString("project")
	user, _ := cmd.Flags().GetString("user")
	linuxUser, _ := cmd.Flags().GetString("linux-user")
	host, _ := cmd.Flags().GetString("host")
	apiHost, _ := cmd.Flags().GetString("api-host")
	machineName, _ := cmd.Flags().GetString("name")
	allowSudo, _ := cmd.Flags().GetBool("allow-sudo")
	interactive, _ := cmd.Flags().GetBool("interactive")
	tunnelURL, _ := cmd.Flags().GetString("tunnel-url")
	hostEntryRaw, _ := cmd.Flags().GetStringArray("host-entry")

	// Parse --host-entry values (format: "IP:DOMAIN")
	var hostEntries []config.HostEntry
	for _, raw := range hostEntryRaw {
		parts := strings.SplitN(raw, ":", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return fmt.Errorf("invalid --host-entry %q: expected format IP:DOMAIN (e.g. 192.168.1.5:db.internal)", raw)
		}
		hostEntries = append(hostEntries, config.HostEntry{IP: parts[0], Domain: parts[1]})
	}
	if len(hostEntries) > 5 {
		return fmt.Errorf("too many --host-entry values: maximum is 5, got %d", len(hostEntries))
	}

	if interactive {
		// TODO: Implement interactive configuration
		fmt.Println("Interactive mode not yet implemented")
		return nil
	}

	// Each OS has its own configure flow, and they share nothing but the flags.
	// Windows uses scheduled-task service registration and Windows paths; macOS
	// uses launchd and creates no accounts at all. Neither can run the Linux
	// logic below, which provisions a login user with useradd — a command that
	// does not exist on macOS.
	params := configureParams{
		Token: token, Tenant: tenant, Org: org, Project: project,
		User: user, Host: host, APIHost: normalizeGRPCAddr(apiHost), MachineName: machineName,
		TunnelURL: tunnelURL,
	}
	if runtime.GOOS == "windows" {
		return runConfigureWindows(params)
	}
	if runtime.GOOS == "darwin" {
		return runConfigureDarwin(params)
	}

	// Validate required flags
	if token == "" || tenant == "" || org == "" || project == "" || user == "" || linuxUser == "" || host == "" {
		return fmt.Errorf("missing required flags: token, tenant, org, project, user, linux-user, and host are required")
	}

	// Create or validate Linux user
	homeDir, err := ensureLinuxUser(linuxUser, allowSudo)
	if err != nil {
		return fmt.Errorf("Linux user setup failed: %w", err)
	}
	fmt.Printf("✓ Linux user '%s' ready (home: %s)\n", linuxUser, homeDir)

	// Determine gRPC URL
	var grpcURL string
	apiHost = normalizeGRPCAddr(apiHost)
	if apiHost != "" {
		// Use provided api-host directly as gRPC address
		grpcURL = apiHost
		fmt.Printf("✓ Using custom gRPC address: %s\n", grpcURL)
	} else {
		// Extract from host (backward compatibility)
		grpcURL = extractGRPCURL(host)
		fmt.Printf("✓ Using default gRPC address: %s (extracted from --host)\n", grpcURL)
	}

	// Create directories. /etc/vsay and /var/log/vsay are left broadly readable
	// (0755) since other local tooling — log shippers, ops scripts — may
	// reasonably expect to read config/logs there. certs/ holds key material
	// and only this (root-run) agent ever needs it, so it's tightened.
	_ = os.MkdirAll("/etc/vsay", 0755) // #nosec G301
	_ = os.MkdirAll("/etc/vsay/certs", 0750)
	_ = os.MkdirAll("/var/log/vsay", 0755) // #nosec G301

	// Download CA cert from backend and pin it locally
	caCertFile, caFingerprint, err := fetchAndSaveCA(host)
	if err != nil {
		fmt.Printf("Warning: could not pin CA cert: %v\n", err)
		fmt.Println("  Agent will use system CA pool for server verification")
	} else if caFingerprint != "" {
		fmt.Println("✓ CA cert pinned — fingerprint (verify out-of-band):")
		fmt.Printf("  SHA256: %s\n", caFingerprint)
		// A fingerprint hash is not secret — it's meant to be compared/shared
		// for out-of-band verification, so world-readable is fine here.
		if err := os.WriteFile("/etc/vsay/certs/ca-fingerprint.txt", []byte(caFingerprint), 0644); err != nil { // #nosec G306
			fmt.Printf("Warning: could not persist CA fingerprint: %v\n", err)
		}
	}

	if err := fetchSignedClientCert(host, token); err != nil {
		return fmt.Errorf("failed to get signed client cert from backend: %w", err)
	}
	fmt.Println("✓ Client cert signed by backend CA (ECDSA P-256, 1-day validity)")

	// Write custom host entries to /etc/hosts before the agent connects
	if len(hostEntries) > 0 {
		if err := appendHostEntries(hostEntries); err != nil {
			return fmt.Errorf("failed to write host entries: %w", err)
		}
		fmt.Printf("✓ %d host entries written to /etc/hosts\n", len(hostEntries))
	}

	// Build tunnel config — enabled automatically when a URL is provided
	tunnelCfg := config.TunnelConfig{
		URL:          tunnelURL,
		Enabled:      tunnelURL != "",
		PollInterval: "10s",
	}

	// Create configuration
	cfg := &config.Config{
		Agent: config.AgentConfig{
			ID:   "",          // Will be set after registration
			Name: machineName, // User-provided machine name
		},
		Server: config.ServerConfig{
			Host:       host,
			GRPCURL:    grpcURL,
			APIHost:    apiHost,
			TLS:        true,
			TokenHash:  token,
			CACertFile: caCertFile,
		},
		Tunnel: tunnelCfg,
		Tenant: config.TenantConfig{
			ID: tenant,
		},
		Org: config.OrgConfig{
			ID: org,
		},
		Project: config.ProjectConfig{
			ID: project,
		},
		PortalUser: config.PortalUserConfig{
			Email: user,
		},
		LinuxUser: config.LinuxUserConfig{
			Username:    linuxUser,
			HomeDir:     homeDir,
			Shell:       "/bin/bash",
			SudoEnabled: allowSudo,
		},
		Permissions: config.PermissionsConfig{
			AllowSudo: allowSudo,
		},
		Logging: config.LoggingConfig{
			Level:      "info",
			File:       "/var/log/vsay/agent.log",
			MaxSizeMB:  100,
			MaxBackups: 5,
		},
		HostEntries: hostEntries,
		Status:      "pending_approval",
	}

	// Save configuration — AES-256-GCM encrypted, key derived from /etc/machine-id.
	// The file is only decryptable on this machine.
	configPath := "/etc/vsay/agent.yaml"
	if err := config.SaveEncrypted(cfg, configPath); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Println("✓ Configuration saved (encrypted) to", configPath)

	// Ensure systemd service is installed and enabled
	if err := setupSystemdService(); err != nil {
		return fmt.Errorf("failed to setup systemd service: %w", err)
	}

	// Start and enable the service
	if err := startAndEnableService(); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	fmt.Println("✓ Agent daemon started and enabled")
	fmt.Println("✓ Agent will auto-start on system boot")
	fmt.Println("")
	fmt.Println("Check status: sudo systemctl status wxt-agent")
	fmt.Println("View logs: sudo journalctl -u wxt-agent -f")

	return nil
}

// generateClientCerts auto-generates a self-signed ECDSA P-256 mTLS client cert + key.
// Skips generation if certs already exist.
func generateClientCerts() error {
	certPath := "/etc/vsay/certs/client-cert.pem"
	keyPath := "/etc/vsay/certs/client-key.pem"

	// Already exists — skip
	if _, err := os.Stat(certPath); err == nil {
		fmt.Println("✓ mTLS client certs already present")
		return nil
	}

	hostname, _ := os.Hostname()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate ECDSA key: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"Vsay Agent"},
			CommonName:   hostname,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	keyDER, _ := x509.MarshalECPrivateKey(key)

	// A cert file is public information (no private key material), so 0644 is
	// intentional here — the client's actual private key below stays 0600.
	certOut, err := os.OpenFile(certPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644) // #nosec G302
	if err != nil {
		return fmt.Errorf("create cert file: %w", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		_ = certOut.Close()
		return fmt.Errorf("encode cert: %w", err)
	}
	if err := certOut.Close(); err != nil {
		return fmt.Errorf("close cert file: %w", err)
	}

	keyOut, err := os.OpenFile(keyPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create key file: %w", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		_ = keyOut.Close()
		return fmt.Errorf("encode key: %w", err)
	}
	if err := keyOut.Close(); err != nil {
		return fmt.Errorf("close key file: %w", err)
	}

	fmt.Println("✓ mTLS client cert + key generated at /etc/vsay/certs/")
	return nil
}

// fetchAndSaveCA downloads the private CA cert from the backend and saves it for TLS pinning.
// Returns (certPath, SHA256-fingerprint-hex, error).
func fetchAndSaveCA(host string) (string, string, error) {
	host = strings.TrimSuffix(host, "/")
	resp, err := http.Get(host + "/ca-cert")
	if err != nil {
		return "", "", fmt.Errorf("fetch CA cert: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("server returned %d", resp.StatusCode)
	}

	caPEM, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return "", "", fmt.Errorf("read CA cert: %w", err)
	}

	block, _ := pem.Decode(caPEM)
	if block == nil {
		return "", "", fmt.Errorf("invalid CA cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", "", fmt.Errorf("parse CA cert: %w", err)
	}

	// Compute SHA-256 fingerprint for out-of-band verification
	sum := sha256.Sum256(cert.Raw)
	fingerprint := fmt.Sprintf("%x", sum)

	// A CA cert is public trust material, not a secret — 0644 is intentional.
	caPath := "/etc/vsay/certs/server-ca.pem"
	if err := os.WriteFile(caPath, caPEM, 0644); err != nil { // #nosec G306
		return "", "", fmt.Errorf("save CA cert: %w", err)
	}
	fmt.Println("✓ CA cert saved at", caPath)
	return caPath, fingerprint, nil
}

// fetchSignedClientCert generates an ECDSA P-256 CSR, sends it to backend, and saves the signed cert.
func fetchSignedClientCert(host, token string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	hostname, _ := os.Hostname()
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			Organization: []string{"Vsay Agent"},
			CommonName:   hostname,
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, key)
	if err != nil {
		return fmt.Errorf("create CSR: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	// POST CSR to backend
	host = strings.TrimSuffix(host, "/")
	req, err := http.NewRequest("POST", host+"/agent/sign-cert", bytes.NewReader(csrPEM))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-pem-file")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("sign-cert request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("backend returned %d for sign-cert", resp.StatusCode)
	}

	signedCertPEM, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return fmt.Errorf("read signed cert: %w", err)
	}

	// Encrypt key and cert before writing — plaintext private key never persists on disk.
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	encKey, err := agent.EncryptPEM(keyPEM)
	if err != nil {
		return fmt.Errorf("encrypt key: %w", err)
	}
	encCert, err := agent.EncryptPEM(signedCertPEM)
	if err != nil {
		return fmt.Errorf("encrypt cert: %w", err)
	}

	if err := os.WriteFile("/etc/vsay/certs/client-key.enc", encKey, 0600); err != nil {
		return fmt.Errorf("save key: %w", err)
	}
	if err := os.WriteFile("/etc/vsay/certs/client-cert.enc", encCert, 0600); err != nil {
		return fmt.Errorf("save cert: %w", err)
	}
	return nil
}

// appendHostEntries writes custom host entries to /etc/hosts under a vsay-managed block.
// Re-running configure will replace the existing block cleanly.
func appendHostEntries(entries []config.HostEntry) error {
	const hostsFile = "/etc/hosts"
	const blockStart = "# wxt-agent managed hosts — do not edit manually"
	const blockEnd = "# end wxt-agent managed hosts"

	// Read current /etc/hosts
	existing, err := os.ReadFile(hostsFile)
	if err != nil {
		return fmt.Errorf("read %s: %w", hostsFile, err)
	}

	// Strip any existing vsay block
	content := string(existing)
	if s := strings.Index(content, blockStart); s != -1 {
		e := strings.Index(content, blockEnd)
		if e != -1 {
			content = content[:s] + content[e+len(blockEnd):]
		}
	}
	content = strings.TrimRight(content, "\n") + "\n"

	// Build new block
	var block strings.Builder
	block.WriteString(blockStart + "\n")
	for _, entry := range entries {
		fmt.Fprintf(&block, "%-20s %s\n", entry.IP, entry.Domain)
	}
	block.WriteString(blockEnd + "\n")

	// hostsFile is the fixed literal "/etc/hosts" above, not request/user input,
	// and must stay world-readable (0644) — every process on the box resolves
	// hostnames through it.
	return os.WriteFile(hostsFile, []byte(content+block.String()), 0644) // #nosec G302,G306,G703
}

// extractGRPCURL extracts gRPC URL from HTTP host
func extractGRPCURL(host string) string {
	// Remove http:// or https://
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")

	// Extract hostname and port
	parts := strings.Split(host, ":")
	if len(parts) >= 2 {
		// Use same hostname, default gRPC port 8081
		return parts[0] + ":8081"
	}
	// If no port specified, use hostname with default gRPC port
	if host != "" {
		return host + ":8081"
	}
	// Default
	return "localhost:8081"
}

// normalizeGRPCAddr turns whatever was passed to --api-host into a bare
// host:port that net.Dial accepts.
//
// The portal hands out an address that often carries a scheme, because the
// same value is used for browser URLs elsewhere. gRPC dials raw TCP, so
// "http://192.168.1.8:8081" fails with "too many colons in address" — a
// confusing error that looks like a TLS problem in the logs. Strip the scheme
// (and any trailing path) rather than making every caller remember to.
func normalizeGRPCAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	for _, scheme := range []string{"https://", "http://", "grpcs://", "grpc://", "tcp://"} {
		addr = strings.TrimPrefix(addr, scheme)
	}
	// Drop anything after the authority, e.g. "host:8081/path".
	if i := strings.IndexAny(addr, "/?#"); i != -1 {
		addr = addr[:i]
	}
	return strings.TrimSuffix(addr, ":")
}

// ensureLinuxUser resolves the account's home directory. It does NOT create
// the account.
//
// It used to run useradd, and adding a login to every endpoint it touched is
// not this product's job: the accounts on a managed machine belong to the
// company's directory, MDM or IT team. EPM enables and disables access for
// accounts that already exist. Creating one silently also left a login behind
// on every machine the agent was ever installed on, which no uninstaller
// removed and no screen in the portal ever showed.
func ensureLinuxUser(username string, allowSudo bool) (string, error) {
	homeDir := "/home/" + username

	if err := exec.Command("id", username).Run(); err != nil { // #nosec G204
		return "", fmt.Errorf(
			"the account %q does not exist on this machine.\n"+
				"This agent does not create accounts — create it first (for example:\n"+
				"  sudo useradd -m -s /bin/bash %s\n"+
				"), then run configure again, or pass --user with an account that exists",
			username, username)
	}

	// Parsed in Go rather than piped through a shell: a username containing
	// shell metacharacters could otherwise inject arbitrary commands.
	if output, err := exec.Command("getent", "passwd", username).Output(); err == nil && len(output) > 0 { // #nosec G204
		fields := strings.Split(strings.TrimSpace(string(output)), ":")
		if len(fields) >= 6 && fields[5] != "" {
			homeDir = fields[5]
		}
	}
	fmt.Printf("✓ Using existing account '%s' (home: %s)\n", username, homeDir)

	if allowSudo {
		// Group membership is also left alone, for the same reason: granting
		// an account sudo is a privilege change the machine's owner makes, not
		// something an installer slips in.
		fmt.Printf("Note: --allow-sudo no longer modifies groups or /etc/sudoers.d.\n")
		fmt.Printf("      Grant '%s' sudo yourself if that is what you intend.\n", username)
	}

	return homeDir, nil
}

// setupSystemdService ensures systemd service is installed (always overwrites to apply updates)
func setupSystemdService() error {
	serviceFile := "/etc/systemd/system/wxt-agent.service"

	// Stop existing service if running (ignore errors if not running)
	if err := exec.Command("systemctl", "stop", "wxt-agent").Run(); err != nil { // #nosec G204
		fmt.Printf("(service was not running: %v)\n", err)
	}

	// Always create/overwrite service file to ensure latest configuration
	serviceContent := `[Unit]
Description=Vsay Agent - Remote Terminal Access
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/wxt-agent start --config /etc/vsay/agent.yaml
Restart=on-failure
RestartSec=10s
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
`

	// systemd unit files are conventionally 0644 (world-readable) — that's the
	// standard every other .service file on the box has, and tools like
	// `systemctl cat`/`status` expect to be able to read them as any user.
	if err := os.WriteFile(serviceFile, []byte(serviceContent), 0644); err != nil { // #nosec G306
		return fmt.Errorf("failed to create service file: %w", err)
	}

	// Reload systemd
	cmd := exec.Command("systemctl", "daemon-reload")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to reload systemd: %w", err)
	}

	return nil
}

// startAndEnableService starts and enables the systemd service
func startAndEnableService() error {
	// Enable service
	cmd := exec.Command("systemctl", "enable", "wxt-agent")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to enable service: %w", err)
	}

	// Start service
	cmd = exec.Command("systemctl", "start", "wxt-agent")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	return nil
}

func runStart(cmd *cobra.Command, args []string) error {
	configPath, _ := cmd.Flags().GetString("config")

	// Guaranteed early marker to the default log file — proves THIS binary ran (with a
	// fresh timestamp) even before config load. If this line never appears in the log,
	// an old binary is running.
	writeBootLog(fmt.Sprintf("=== wxt-agent %s starting (config=%s) ===", version, configPath))

	// Load configuration — handles both encrypted (new) and plaintext (old) formats.
	cfg, err := config.LoadEncrypted(configPath)
	if err != nil {
		// Config load failed before the logger is up. Write the reason to the default
		// log file so a background service (no console) is still diagnosable.
		writeBootError(fmt.Sprintf("failed to load config %s: %v", configPath, err))
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Setup logger with backend-style formatting
	loggerConfig := zap.Config{
		Level:       zap.NewAtomicLevelAt(zap.InfoLevel),
		Development: false,
		Encoding:    "console",
		EncoderConfig: zapcore.EncoderConfig{
			TimeKey:       "ts",
			LevelKey:      "level",
			NameKey:       "logger",
			CallerKey:     "",
			FunctionKey:   zapcore.OmitKey,
			MessageKey:    "msg",
			StacktraceKey: "stacktrace",
			LineEnding:    zapcore.DefaultLineEnding,
			EncodeLevel:   zapcore.CapitalLevelEncoder,
			EncodeTime: func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
				enc.AppendString(t.Format("2006-01-02 15:04:05"))
			},
			EncodeDuration:   zapcore.StringDurationEncoder,
			EncodeCaller:     zapcore.ShortCallerEncoder,
			ConsoleSeparator: " | ",
		},
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
	}

	// Write logs to BOTH stdout and a log file. Without the file sink, a background
	// service (Windows scheduled task as SYSTEM, or systemd) has no visible log —
	// this is what makes Windows startup issues diagnosable. The file is opened
	// directly (not via zap's OutputPaths) to avoid zap's Windows drive-letter path
	// parsing issue (C:\ read as a URL scheme).
	//
	// Fall back to the platform default path if the config has no log file set (e.g.
	// an older config), so a log ALWAYS appears.
	logFilePath := cfg.Logging.File
	if logFilePath == "" {
		logFilePath = defaultLogFile()
	}
	logSinks := []zapcore.WriteSyncer{zapcore.AddSync(os.Stdout)}
	if logFilePath != "" {
		// logFilePath is this agent's own config value (cfg.Logging.File) or the
		// platform default, never request/user input. Left world-readable
		// (0755/0644) since ops/monitoring tooling on the box may reasonably
		// expect to read agent logs.
		if err := os.MkdirAll(filepath.Dir(logFilePath), 0o755); err != nil { // #nosec G301,G304
			fmt.Fprintf(os.Stderr, "warning: cannot create log dir %s: %v\n", filepath.Dir(logFilePath), err)
		}
		if lf, ferr := os.OpenFile(logFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); ferr == nil { // #nosec G302,G304
			logSinks = append(logSinks, zapcore.AddSync(lf))
		} else {
			fmt.Fprintf(os.Stderr, "warning: cannot open log file %s: %v\n", logFilePath, ferr)
		}
	}
	logger := zap.New(zapcore.NewCore(
		zapcore.NewConsoleEncoder(loggerConfig.EncoderConfig),
		zapcore.NewMultiWriteSyncer(logSinks...),
		loggerConfig.Level,
	))
	defer logger.Sync()

	logger.Info("Starting wxt-agent",
		zap.String("version", version),
		zap.String("agent_id", cfg.Agent.ID),
		zap.String("linux_user", cfg.LinuxUser.Username),
	)

	// Propagate the compiled version into the agent package so it gets
	// reported to the backend in register metadata (for self-update).
	agent.BuildVersion = version

	// Anything that goes wrong from here on is reported through the logger
	// before it is returned. Returning it alone sends it to cobra, which hands
	// it to log.Fatal and so to stderr — and a Windows scheduled task running as
	// SYSTEM has no stderr. That is why a crashing agent left a log file ending
	// mid-startup with no reason given, restarting every few minutes.
	fail := func(err error) error {
		logger.Error("Agent stopped", zap.Error(err))
		_ = logger.Sync()
		return err
	}

	// Create agent
	agt, err := agent.New(cfg, logger)
	if err != nil {
		return fail(fmt.Errorf("failed to create agent: %w", err))
	}

	// Settings pushed from the portal are written back here, so they survive a
	// restart rather than reverting silently.
	agt.SetConfigPath(configPath)

	// Start agent
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errChan := make(chan error, 1)
	go func() {
		if err := agt.Start(ctx); err != nil {
			errChan <- err
		}
	}()

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errChan:
		return fail(fmt.Errorf("agent error: %w", err))
	case sig := <-sigChan:
		logger.Info("Received signal, shutting down", zap.String("signal", sig.String()))
		cancel()
		time.Sleep(2 * time.Second)
	}

	return nil
}

func runValidate(cmd *cobra.Command, args []string) error {
	// TODO: Implement configuration validation
	fmt.Println("Validation not yet implemented")
	return nil
}

func runShowConfig(cmd *cobra.Command, args []string) error {
	configPath, _ := cmd.Flags().GetString("config")

	cfg, err := config.LoadEncrypted(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config from %s: %w", configPath, err)
	}

	// Marshal back to YAML for human-readable output.
	out, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	fmt.Printf("# Decrypted config from %s\n", configPath)
	fmt.Print(string(out))
	return nil
}
