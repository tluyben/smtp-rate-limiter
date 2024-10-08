# 📧 Go SMTP Rate-limiting Server Server

## 📚 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Rate Limiting](#rate-limiting)
- [Logging and Monitoring](#logging-and-monitoring)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## 🌟 Overview

This Go SMTP Forwarding Server is a powerful and flexible email routing solution. It accepts SMTP connections on localhost and forwards them to a configured SMTP server, with advanced features like rate limiting, logging, and alternate server support.

## 🚀 Features

- 🔄 SMTP forwarding
- ⏱️ Configurable rate limiting (hourly, daily, monthly)
- 📊 Rate limit warnings
- 📝 Logging to stderr
- 🐞 Optional Sentry integration for error tracking
- 🔀 Alternate SMTP server support
- ✉️ 'From' address restriction
- 🔐 Support for plain, SSL, and TLS encryption

## 🛠️ Requirements

- Go 1.16+
- GitHub.com/joho/godotenv
- GitHub.com/getsentry/sentry-go

## 📥 Installation

1. Clone the repository:

   ```
   git clone https://github.com/yourusername/go-smtp-forwarder.git
   cd go-smtp-forwarder
   ```

2. Install dependencies:
   ```
   go get github.com/joho/godotenv
   go get github.com/getsentry/sentry-go
   ```

## ⚙️ Configuration

Create a `.env` file in the project root with the following variables:

```
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=your_username
SMTP_PASSWORD=your_password
SMTP_ENCRYPTION=starttls
DAILY_RATE_LIMIT=100
HOURLY_RATE_LIMIT=10
MONTHLY_RATE_LIMIT=1000
WARN_RATE=10
SENTRY_DSN=your_sentry_dsn
ALT_SMTP_HOST=alt.smtp.example.com
ALT_SMTP_PORT=465
ALT_SMTP_USER=alt_username
ALT_SMTP_PASSWORD=alt_password
ALT_SMTP_ENCRYPTION=ssl
FROM=allowed@example.com,another@example.com
```

## 🚀 Usage

Run the server:

```
go run main.go
```

The server will start listening on `127.0.0.1:25` for incoming SMTP connections.

Example send:

```
swaks --to recipient@example.com \
      --from sender@example.com \
      --header "Subject: Test Email" \
      --body "This is a test email sent using swaks." \
      --server 127.0.0.1 \
      --port 25

swaks --to rep1@example.com,rep2@example.com \
      --from support@example.com \
      --header "Subject: Test Email" \
      --body "This is a test email sent using swaks." \
      --server 127.0.0.1 \
      --port 25

swaks --to "Jim Johnson <rep1@example.com>","Frank Frakkel <rep2@example.com>" \
      --from "Support Team <support@example.com>" \
      --header "Subject: Test Email" \
      --body "This is a test email sent using swaks." \
      --server 127.0.0.1 \
      --port 25

swaks --to "Jim Johnson <rep1@example.com>" \
      --from "Support Team <support@example.com>" \
      --header "Subject: Test Email with Reply-To" \
      --header "Reply-To: Customer Service <someone@example.com>" \
      --body "This is a test email sent using swaks with a Reply-To header." \
      --server 127.0.0.1 \
      --port 25

swaks --to "Jim Johnson <rep1@example.com>" \
      --from "Support Team <support@example.com>" \
      --header "Subject: Test Email with Reply-To" \
      --header "Reply-To: Customer Service <someone@example.com>" \
      --header "List-Unsubscribe: <mailto:unsubscribe@example.com?subject=unsubscribe>" \
      --body "This is a test email sent using swaks with a Reply-To header." \
	  --auth-user slop \
	  --auth-password withbob \
      --attach-type "text/plain" \
      --attach @"./README.md" \
      --server 127.0.0.1 \
      --port 25
```

## 🚦 Rate Limiting

- Hourly, daily, and monthly rate limits can be set.
- Set a limit to 0 for unlimited.
- If multiple limits are set, all are enforced (e.g., you can't exceed monthly even if daily is unlimited).

## 📊 Logging and Monitoring

- All logs are output to stderr.
- If `SENTRY_DSN` is configured, errors and warnings are also sent to Sentry.
- Rate limit warnings are triggered when usage reaches `WARN_RATE`% of the limit.

## 🔒 Security Considerations

- The server accepts any username/password on localhost. Ensure it's not exposed to the public internet.
- Use strong passwords for your SMTP servers.
- Regularly update the allowed 'From' addresses if using that feature.

## 🔍 Troubleshooting

1. **Can't connect to the server**: Ensure it's running and listening on 127.0.0.1:25.
2. **Emails not being sent**: Check your SMTP server configuration and credentials.
3. **Rate limits not working**: Verify the rate limit settings in your .env file.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License.
