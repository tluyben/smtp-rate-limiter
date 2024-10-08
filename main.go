package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/mail"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/joho/godotenv"
)

type Config struct {
	SmtpHost         string
	SmtpPort         int
	SmtpUser         string
	SmtpPassword     string
	SmtpEncryption   string
	DailyRateLimit   int
	HourlyRateLimit  int
	MonthlyRateLimit int
	WarnRate         int
	SentryDSN        string
	AltSmtpHost      string
	AltSmtpPort      int
	AltSmtpUser      string
	AltSmtpPassword  string
	AltSmtpEncryption string
	FromAddresses    []string
	BindAddress      string
}

type RateLimiter struct {
	daily   int
	hourly  int
	monthly int
	mutex   sync.Mutex
}

var (
	config Config
	limiter RateLimiter
)

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Println("Error loading .env file")
	}

	config = Config{
		SmtpHost:         getEnv("SMTP_HOST", ""),
		SmtpPort:         getEnvAsInt("SMTP_PORT", 25),
		SmtpUser:         getEnv("SMTP_USER", ""),
		SmtpPassword:     getEnv("SMTP_PASSWORD", ""),
		SmtpEncryption:   getEnv("SMTP_ENCRYPTION", "plain"),
		DailyRateLimit:   getEnvAsInt("DAILY_RATE_LIMIT", 0),
		HourlyRateLimit:  getEnvAsInt("HOURLY_RATE_LIMIT", 0),
		MonthlyRateLimit: getEnvAsInt("MONTHLY_RATE_LIMIT", 0),
		WarnRate:         getEnvAsInt("WARN_RATE", 10),
		SentryDSN:        getEnv("SENTRY_DSN", ""),
		AltSmtpHost:      getEnv("ALT_SMTP_HOST", ""),
		AltSmtpPort:      getEnvAsInt("ALT_SMTP_PORT", 25),
		AltSmtpUser:      getEnv("ALT_SMTP_USER", ""),
		AltSmtpPassword:  getEnv("ALT_SMTP_PASSWORD", ""),
		AltSmtpEncryption: getEnv("ALT_SMTP_ENCRYPTION", "plain"),
		FromAddresses:    parseFromAddresses(getEnv("FROM", "")),
		BindAddress:      getEnv("BIND_ADDRESS", "127.0.0.1"),
	}

	if config.SentryDSN != "" {
		err := sentry.Init(sentry.ClientOptions{
			Dsn: config.SentryDSN,
		})
		if err != nil {
			log.Fatalf("sentry.Init: %s", err)
		}
	}

	limiter = RateLimiter{
		daily:   0,
		hourly:  0,
		monthly: 0,
	}
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func getEnvAsInt(key string, fallback int) int {
	strVal := getEnv(key, "")
	if value, err := strconv.Atoi(strVal); err == nil {
		return value
	}
	return fallback
}

func main() {
	listener, err := net.Listen("tcp", config.BindAddress+":25")
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	log.Println("SMTP server started on", config.BindAddress+":25")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go handleConnection(conn)
	}
}

func parseFromAddresses(fromEnv string) []string {
	if fromEnv == "" {
		return nil
	}
	addresses := strings.Split(fromEnv, ",")
	var validAddresses []string
	for _, addr := range addresses {
		trimmedAddr := strings.TrimSpace(addr)
		if trimmedAddr != "" {
			validAddresses = append(validAddresses, trimmedAddr)
		}
	}
	if len(validAddresses) == 0 {
		return nil
	}
	return validAddresses
}
func handleConnection(conn net.Conn) {
	defer conn.Close()

	// SMTP handshake
	conn.Write([]byte("220 SMTP Server Ready\r\n"))

	scanner := bufio.NewScanner(conn)
	var data bytes.Buffer
	var inData bool

	for scanner.Scan() {
		line := scanner.Text()
		
		if inData {
			if line == "." {
				inData = false
				log.Println("Forwarding email")
				if err := forwardEmail(data.Bytes()); err != nil {
					log.Printf("Error forwarding email: %v", err)
					conn.Write([]byte("554 Transaction failed\r\n"))
				} else {
					conn.Write([]byte("250 OK\r\n"))
				}
				data.Reset()
			} else {
				data.WriteString(line + "\r\n")
			}
		} else {
			switch {
			case strings.HasPrefix(line, "HELO") || strings.HasPrefix(line, "EHLO"):
				conn.Write([]byte("250-Hello\r\n"))
				conn.Write([]byte("250 AUTH LOGIN PLAIN\r\n")) // Advertise AUTH, but we'll ignore it
			case strings.HasPrefix(line, "AUTH"):
				// Ignore AUTH command and respond as if authenticated
				conn.Write([]byte("235 Authentication successful\r\n"))
			case strings.HasPrefix(line, "MAIL FROM:"):
				conn.Write([]byte("250 OK\r\n"))
			case strings.HasPrefix(line, "RCPT TO:"):
				conn.Write([]byte("250 OK\r\n"))
			case line == "DATA":
				inData = true
				conn.Write([]byte("354 Start mail input; end with <CRLF>.<CRLF>\r\n"))
			case line == "QUIT":
				conn.Write([]byte("221 Bye\r\n"))
				return
			default:
				conn.Write([]byte("500 Command not recognized\r\n"))
			}
		}
	}
}


func extractAddresses(data []byte) (from string, to []string) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "From:") {
			from = strings.TrimSpace(strings.TrimPrefix(line, "From:"))
		} else if strings.HasPrefix(line, "To:") {
			toLine := strings.TrimSpace(strings.TrimPrefix(line, "To:"))
			to = parseAddressList(toLine)
		}
		if from != "" && len(to) > 0 {
			break
		}
	}
	return
}

func parseAddressList(addressList string) []string {
	var parsed []string
	addresses, err := mail.ParseAddressList(addressList)
	if err != nil {
		log.Printf("Error parsing address list: %v", err)
		return strings.Split(addressList, ",")
	}
	for _, addr := range addresses {
		parsed = append(parsed, addr.Address)
	}
	return parsed
}

func forwardEmail(data []byte) error {
	from, to := extractAddresses(data)

	if !checkRateLimit() {
		return fmt.Errorf("rate limit exceeded")
	}

	if len(config.FromAddresses) > 0 && !isAllowedFrom(extractEmailAddress(from)) {
		logMessage(fmt.Sprintf("Unauthorized 'From' address: %s", from), true)
		return fmt.Errorf("unauthorized 'From' address")
	}

	var err error
	if config.AltSmtpHost != "" && config.SentryDSN == "" {
		err = sendEmail(config.AltSmtpHost, config.AltSmtpPort, config.AltSmtpUser, config.AltSmtpPassword, config.AltSmtpEncryption, from, to, data)
	} else {
		err = sendEmail(config.SmtpHost, config.SmtpPort, config.SmtpUser, config.SmtpPassword, config.SmtpEncryption, from, to, data)
	}

	if err != nil && config.AltSmtpHost != "" {
		err = sendEmail(config.AltSmtpHost, config.AltSmtpPort, config.AltSmtpUser, config.AltSmtpPassword, config.AltSmtpEncryption, from, to, data)
	}

	return err
}

func extractEmailAddress(address string) string {
	addr, err := mail.ParseAddress(address)
	if err != nil {
		log.Printf("Error parsing email address: %v", err)
		return address
	}
	return addr.Address
}

func sendEmail(host string, port int, user, password, encryption, from string, to []string, data []byte) error {
	log.Printf("Attempting to send email via %s:%d using %s encryption", host, port, encryption)

	var conn net.Conn
	var err error
	address := fmt.Sprintf("%s:%d", host, port)

	switch encryption {
	case "ssl", "tls":
		tlsConfig := &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: false,
		}
		log.Printf("Attempting TLS connection to %s", address)
		conn, err = tls.Dial("tcp", address, tlsConfig)
	default:
		log.Printf("Attempting plain TCP connection to %s", address)
		conn, err = net.Dial("tcp", address)
	}

	if err != nil {
		log.Printf("Error connecting to %s: %v", address, err)
		return fmt.Errorf("connection error: %v", err)
	}
	defer conn.Close()

	c, err := smtp.NewClient(conn, host)
	if err != nil {
		log.Printf("Error creating SMTP client: %v", err)
		return fmt.Errorf("SMTP client creation error: %v", err)
	}
	defer c.Close()

	if encryption == "starttls" {
		log.Println("Attempting STARTTLS")
		err = c.StartTLS(&tls.Config{ServerName: host})
		if err != nil {
			log.Printf("StartTLS error: %v", err)
			return fmt.Errorf("StartTLS error: %v", err)
		}
	}

	if user != "" {
		auth := smtp.PlainAuth("", user, password, host)
		if err = c.Auth(auth); err != nil {
			log.Printf("Auth error: %v", err)
			return fmt.Errorf("auth error: %v", err)
		}
	}

	if err = c.Mail(extractEmailAddress(from)); err != nil {
		log.Printf("MAIL FROM error: %v", err)
		return fmt.Errorf("MAIL FROM error: %v", err)
	}

	for _, recipient := range to {
		if err = c.Rcpt(recipient); err != nil {
			log.Printf("RCPT TO error for %s: %v", recipient, err)
			return fmt.Errorf("RCPT TO error for %s: %v", recipient, err)
		}
	}

	w, err := c.Data()
	if err != nil {
		log.Printf("DATA command error: %v", err)
		return fmt.Errorf("DATA command error: %v", err)
	}

	_, err = w.Write(data)
	if err != nil {
		log.Printf("Error writing email data: %v", err)
		return fmt.Errorf("error writing email data: %v", err)
	}

	err = w.Close()
	if err != nil {
		log.Printf("Error closing data writer: %v", err)
		return fmt.Errorf("error closing data writer: %v", err)
	}

	err = c.Quit()
	if err != nil {
		log.Printf("QUIT command error: %v", err)
		return fmt.Errorf("QUIT command error: %v", err)
	}

	log.Println("Email sent successfully")
	return nil
}
func checkRateLimit() bool {
	limiter.mutex.Lock()
	defer limiter.mutex.Unlock()

	now := time.Now()
	hour := now.Hour()
	day := now.Day()
	month := int(now.Month())

	if config.HourlyRateLimit > 0 && limiter.hourly >= config.HourlyRateLimit {
		logMessage("Hourly rate limit exceeded", true)
		return false
	}

	if config.DailyRateLimit > 0 && limiter.daily >= config.DailyRateLimit {
		logMessage("Daily rate limit exceeded", true)
		return false
	}

	if config.MonthlyRateLimit > 0 && limiter.monthly >= config.MonthlyRateLimit {
		logMessage("Monthly rate limit exceeded", true)
		return false
	}

	limiter.hourly++
	limiter.daily++
	limiter.monthly++

	// Check warn rate
	checkWarnRate("hourly", limiter.hourly, config.HourlyRateLimit)
	checkWarnRate("daily", limiter.daily, config.DailyRateLimit)
	checkWarnRate("monthly", limiter.monthly, config.MonthlyRateLimit)

	// Reset counters if necessary
	if hour == 0 && limiter.hourly > 0 {
		limiter.hourly = 0
	}
	if day == 1 && limiter.daily > 0 {
		limiter.daily = 0
	}
	if month == 1 && limiter.monthly > 0 {
		limiter.monthly = 0
	}

	return true
}

func checkWarnRate(period string, current, limit int) {
	if limit > 0 {
		percentage := float64(current) / float64(limit) * 100
		if percentage >= float64(100-config.WarnRate) {
			logMessage(fmt.Sprintf("%s rate is at %.2f%% (%d/%d)", period, percentage, current, limit), false)
		}
	}
}

func isAllowedFrom(from string) bool {
	for _, allowed := range config.FromAddresses {
		if strings.TrimSpace(allowed) == strings.TrimSpace(from) {
			return true
		}
	}
	return false
}

func logMessage(message string, isError bool) {
	log.Println(message)
	if config.SentryDSN != "" {
		if isError {
			sentry.CaptureException(fmt.Errorf(message))
		} else {
			sentry.CaptureMessage(message)
		}
	}
}