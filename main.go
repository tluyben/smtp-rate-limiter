package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"log"
	"net"
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
		FromAddresses:    strings.Split(getEnv("FROM", ""), ","),
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
	listener, err := net.Listen("tcp", "127.0.0.1:25")
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// SMTP handshake
	conn.Write([]byte("220 SMTP Server Ready\r\n"))

	scanner := bufio.NewScanner(conn)
	var from, to string
	var data bytes.Buffer
	var inData bool

	for scanner.Scan() {
		line := scanner.Text()
		
		if inData {
			if line == "." {
				inData = false
				if err := forwardEmail(from, to, data.Bytes()); err != nil {
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
				from = strings.TrimPrefix(line, "MAIL FROM:")
				conn.Write([]byte("250 OK\r\n"))
			case strings.HasPrefix(line, "RCPT TO:"):
				to = strings.TrimPrefix(line, "RCPT TO:")
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

func forwardEmail(from, to string, data []byte) error {
	if !checkRateLimit() {
		return fmt.Errorf("rate limit exceeded")
	}

	if len(config.FromAddresses) > 0 && !isAllowedFrom(from) {
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

func sendEmail(host string, port int, user, password, encryption, from, to string, data []byte) error {
	auth := smtp.PlainAuth("", user, password, host)

	var conn net.Conn
	var err error

	switch encryption {
	case "ssl", "tls":
		conn, err = tls.Dial("tcp", fmt.Sprintf("%s:%d", host, port), nil)
	default:
		conn, err = net.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	}

	if err != nil {
		return err
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer client.Close()

	if encryption == "tls" {
		if err = client.StartTLS(nil); err != nil {
			return err
		}
	}

	if err = client.Auth(auth); err != nil {
		return err
	}

	if err = client.Mail(from); err != nil {
		return err
	}

	if err = client.Rcpt(to); err != nil {
		return err
	}

	writer, err := client.Data()
	if err != nil {
		return err
	}

	_, err = writer.Write(data)
	if err != nil {
		return err
	}

	err = writer.Close()
	if err != nil {
		return err
	}

	return client.Quit()
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