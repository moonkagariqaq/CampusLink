package main

import (
	"bufio"
	"esurfing/network"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// xmlEscape escapes special XML characters in user input.
func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;", "'", "&apos;")
	return r.Replace(s)
}

// Client manages the authentication lifecycle.
type Client struct {
	options       Options
	states        *States
	session       *Session
	httpClient    *http.Client
	keepURL       string
	termURL       string
	keepRetry     string
	retryCount    int
	tick          int64
	lastStatus    network.ConnectivityStatus
	statusChanged bool
}

// Options holds login credentials.
type Options struct {
	LoginUser     string
	LoginPassword string
	SMSCode       string
	SMSReader     func() string
	DisableSMS    bool
}

func NewClient(opts Options, states *States, session *Session, baseTransport ...http.RoundTripper) *Client {
	httpClient := network.NewHTTPClient(states, baseTransport...)
	return &Client{
		options:       opts,
		states:        states,
		session:       session,
		httpClient:    httpClient,
		lastStatus:    -1, // force first log
		statusChanged: true,
	}
}

// Run starts the main client loop.
func (c *Client) Run() {
	for c.states.IsRunning() {
		if c.states.IsLogged() {
			nowMs := time.Now().UnixMilli()
			retryMs, err := strconv.ParseInt(c.keepRetry, 10, 64)
			if err == nil && retryMs > 0 && nowMs-c.tick >= retryMs*1000 {
				log.Println("[Client] Sending heartbeat...")
				if err := c.heartbeat(c.states.GetTicket()); err != nil {
					log.Printf("[Client] Heartbeat error: %v", err)
					publicFailure("心跳", err)
					c.states.SetLogged(false)
					c.session.Free()
					c.states.SetAlgoID("00000000-0000-0000-0000-000000000000")
					c.statusChanged = true
					continue
				}
				log.Printf("[Client] Heartbeat OK, next retry: %ss", c.keepRetry)
				report("heartbeat", "心跳成功，连接保持中。")
				c.tick = time.Now().UnixMilli()
			}
			c.pause(time.Second)
			continue
		}

		status := network.DetectConfigWithClient(c.httpClient, c.states, c.statusChanged)
		c.statusChanged = status.Status != c.lastStatus
		c.lastStatus = status.Status

		switch status.Status {
		case network.StatusSuccess:
			if !c.states.IsLogged() && c.statusChanged {
				log.Println("[Client] Network is connected.")
				report("external", "当前网络已联网，但尚未由本客户端认证。")
			}
			c.pause(10 * time.Second)

		case network.StatusRequireAuthorization:
			if c.statusChanged {
				log.Println("[Client] Network requires authorization, starting auth flow...")
			}
			c.states.SetLogged(false)
			// Apply detected config to states
			c.states.SetAuthURL(status.AuthURL)
			c.states.SetTicketURL(status.TicketURL)
			c.states.SetUserIP(status.UserIP)
			c.states.SetAcIP(status.AcIP)
			if status.SchoolID != "" {
				c.states.SetSchoolID(status.SchoolID)
			}
			if status.Domain != "" {
				c.states.SetDomain(status.Domain)
			}
			if status.Area != "" {
				c.states.SetArea(status.Area)
			}
			if len(status.ExtraCfgURL) > 0 {
				c.states.SetExtraCfgURL(status.ExtraCfgURL)
			}
			c.authorization()
			if !c.states.IsLogged() && c.states.IsRunning() {
				c.pause(30 * time.Second)
			}
			c.statusChanged = true // force log after auth attempt

		case network.StatusRequestError:
			if c.statusChanged {
				log.Println("[Client] Request Error - see detailed logs above")
			}
			if c.statusChanged {
				report("error", "认证入口不可达或返回格式不兼容，稍后重试。")
			}
			c.pause(15 * time.Second)
		}
	}
}

func (c *Client) pause(d time.Duration) {
	deadline := time.Now().Add(d)
	for c.states.IsRunning() && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
}

func (c *Client) authorization() {
	var code string
	if c.options.DisableSMS {
		code = ""
	} else if strings.TrimSpace(c.options.SMSCode) == "" {
		code = c.checkSMSVerify()
	} else {
		code = c.options.SMSCode
	}

	if !c.states.IsRunning() {
		return
	}
	report("status", "正在建立加密认证会话……")

	c.initSession()
	if !c.session.IsInitialized() {
		log.Println("[Client] Session initialization failed, cannot proceed.")
		report("error", "无法初始化认证加密算法；本版本可能不兼容服务器。")
		c.states.SetRunning(false)
		return
	}

	c.retryCount = 0
	log.Printf("[Client] Algo Id: %s", c.session.GetAlgoID())
	log.Printf("[Client] Client ID: %s", c.states.GetClientID())
	log.Printf("[Client] Client IP: %s", c.states.GetUserIP())
	log.Printf("[Client] AC IP: %s", c.states.GetAcIP())
	log.Printf("[Client] MAC: %s", c.states.GetMacAddress())
	log.Printf("[Client] SchoolID: %s, Domain: %s, Area: %s", c.states.GetSchoolID(), c.states.GetDomain(), c.states.GetArea())

	ticket, err := c.getTicket()
	if err != nil {
		log.Printf("[Client] Get ticket error: %v", err)
		publicFailure("获取认证票据", err)
		c.states.SetRunning(false)
		return
	}
	c.states.SetTicket(ticket)
	log.Printf("[Client] Ticket: %s", c.states.GetTicket())

	if err := c.login(code); err != nil {
		log.Printf("[Client] Login error: %v", err)
		publicFailure("登录", err)
		c.states.SetRunning(false)
		return
	}

	if c.keepURL == "" {
		log.Println("[Client] KeepUrl is empty, login may have failed.")
		report("error", "服务器未返回心跳地址，登录未通过。")
		c.session.Free()
		c.states.SetRunning(false)
		return
	}

	c.tick = time.Now().UnixMilli()
	c.states.SetLogged(true)
	log.Println("[Client] The login has been authorized.")
	report("online", "认证成功，正在维持校园网连接。")
	if seconds, err := strconv.Atoi(c.keepRetry); err == nil {
		report("status", fmt.Sprintf("服务器要求每 %d 秒发送心跳。", seconds))
	}
}

func (c *Client) checkSMSVerify() string {
	extraCfg := c.states.GetExtraCfgURL()
	if network.CheckVerifyCodeStatus(c.states, c.httpClient, c.options.LoginUser, extraCfg) &&
		network.GetVerifyCode(c.states, c.httpClient, c.options.LoginUser, extraCfg) {
		log.Println("This login requires a SMS verification code.")
		if c.options.SMSReader != nil {
			return c.options.SMSReader()
		}
		reader := bufio.NewReader(os.Stdin)
		for {
			fmt.Print("Input Code: ")
			input, _ := reader.ReadString('\n')
			code := strings.TrimSpace(input)
			if code != "" {
				return code
			}
		}
	}
	return ""
}

func (c *Client) initSession() {
	log.Printf("[Client] Initializing session, TicketURL: %s, AlgoID: %s", c.states.GetTicketURL(), c.states.GetAlgoID())
	body, err := network.PostRaw(c.httpClient, c.states.GetTicketURL(), c.states.GetAlgoID(), c.states)
	if err != nil {
		log.Printf("[Client] Init session error: %v", err)
		return
	}
	log.Printf("[Client] Session ZSM response: %d bytes", len(body))
	c.session.Initialize(body)
	if c.session.IsInitialized() {
		c.states.SetAlgoID(c.session.GetAlgoID())
	}
	log.Printf("[Client] Session initialized: %v, AlgoID: %s", c.session.IsInitialized(), c.session.GetAlgoID())
}

func (c *Client) getTicket() (string, error) {
	for {
		ticket, err := c.getTicketAttempt()
		if err == nil {
			return ticket, nil
		}
		if (!strings.Contains(err.Error(), "empty ticket") && !strings.Contains(err.Error(), "server-code 1")) || !c.session.NextCipher() {
			return "", err
		}
	}
}

func (c *Client) getTicketAttempt() (string, error) {
	curTime := time.Now().Format("2006-01-02 15:04:05")
	payload := fmt.Sprintf(
		`<?xml version="1.0" encoding="utf-8"?>
<request>
    <user-agent>%s</user-agent>
    <client-id>%s</client-id>
    <local-time>%s</local-time>
    <host-name>%s</host-name>
    <ipv4>%s</ipv4>
    <ipv6></ipv6>
    <mac>%s</mac>
    <ostag>%s</ostag>
    <gwip>%s</gwip>
</request>
`,
		UserAgent,
		c.states.GetClientID(),
		curTime,
		HostName,
		c.states.GetUserIP(),
		c.states.GetMacAddress(),
		HostName,
		c.states.GetAcIP(),
	)

	log.Printf("[Client] getTicket payload: %s", payload)
	encrypted, err := c.session.Encrypt(payload)
	if err != nil {
		return "", fmt.Errorf("encrypt ticket payload: %w", err)
	}
	log.Printf("[Client] getTicket encrypted (first 200): %.200s", encrypted)

	data, err := network.Post(c.httpClient, c.states.GetTicketURL(), encrypted, c.states, nil)
	if err != nil {
		return "", err
	}
	log.Printf("[Client] getTicket raw response (first 500): %.500s", data)
	report("diagnostic", fmt.Sprintf("票据响应：%d 字节", len(data)))
	data = strings.TrimSpace(data)

	decrypted, err := c.session.Decrypt(data)
	if err != nil {
		return "", fmt.Errorf("decrypt ticket response: %w", err)
	}
	log.Printf("[Client] getTicket decrypted: %s", decrypted)
	report("diagnostic", fmt.Sprintf("解密结果：%d 字节，XML=%v", len(decrypted), strings.Contains(decrypted, "<")))

	ticket := extractXMLTag(decrypted, "ticket")
	if ticket == "" {
		respCode := extractXMLTag(decrypted, "response-code")
		respMsg := extractXMLTag(decrypted, "response-msg")
		return "", fmt.Errorf("empty ticket, response-code: %s, msg: %s", respCode, respMsg)
	}
	return ticket, nil
}

func (c *Client) login(code string) error {
	c.keepURL = ""
	c.termURL = ""
	curTime := time.Now().Format("2006-01-02 15:04:05")
	var codeTag string
	if code != "" {
		codeTag = fmt.Sprintf("    <code>%s</code>\n", xmlEscape(code))
	}

	payload := fmt.Sprintf(
		`<?xml version="1.0" encoding="utf-8"?>
<request>
    <user-agent>%s</user-agent>
    <client-id>%s</client-id>
    <ticket>%s</ticket>
    <local-time>%s</local-time>
    <userid>%s</userid>
    <passwd>%s</passwd>
%s</request>
`,
		UserAgent,
		c.states.GetClientID(),
		c.states.GetTicket(),
		curTime,
		xmlEscape(c.options.LoginUser),
		xmlEscape(c.options.LoginPassword),
		codeTag,
	)

	log.Printf("[Client] login payload: %s", payload)
	encrypted, err := c.session.Encrypt(payload)
	if err != nil {
		return fmt.Errorf("encrypt login payload: %w", err)
	}
	log.Printf("[Client] login encrypted (first 200): %.200s", encrypted)

	data, err := network.Post(c.httpClient, c.states.GetAuthURL(), encrypted, c.states, nil)
	if err != nil {
		return err
	}
	log.Printf("[Client] login raw response (first 500): %.500s", data)

	decrypted, err := c.session.Decrypt(data)
	if err != nil {
		return fmt.Errorf("decrypt login response: %w", err)
	}
	log.Printf("[Client] login decrypted: %s", decrypted)
	responseCode := extractXMLTag(decrypted, "response-code")
	if responseCode != "" && responseCode != "0" {
		return fmt.Errorf("response-code: %s", responseCode)
	}

	c.keepURL = extractXMLTag(decrypted, "keep-url")
	c.termURL = extractXMLTag(decrypted, "term-url")
	c.keepRetry = extractXMLTag(decrypted, "keep-retry")
	if c.keepRetry == "" {
		c.keepRetry = "180"
	}
	return nil
}

func (c *Client) heartbeat(ticket string) error {
	curTime := time.Now().Format("2006-01-02 15:04:05")
	payload := fmt.Sprintf(
		`<?xml version="1.0" encoding="utf-8"?>
<request>
    <user-agent>%s</user-agent>
    <client-id>%s</client-id>
    <local-time>%s</local-time>
    <host-name>%s</host-name>
    <ipv4>%s</ipv4>
    <ticket>%s</ticket>
    <ipv6></ipv6>
    <mac>%s</mac>
    <ostag>%s</ostag>
</request>
`,
		UserAgent,
		c.states.GetClientID(),
		curTime,
		HostName,
		c.states.GetUserIP(),
		ticket,
		c.states.GetMacAddress(),
		HostName,
	)

	encrypted, err := c.session.Encrypt(payload)
	if err != nil {
		return err
	}
	targetURL := c.keepURL
	if targetURL == "" {
		targetURL = c.states.GetAuthURL()
	}
	data, err := network.Post(c.httpClient, targetURL, encrypted, c.states, nil)
	if err != nil {
		return err
	}
	decrypted, err := c.session.Decrypt(data)
	if err != nil {
		return err
	}
	code := extractXMLTag(decrypted, "response-code")
	if code != "" && code != "0" {
		return fmt.Errorf("response-code: %s", code)
	}
	interval := extractXMLTag(decrypted, "interval")
	if interval == "" && code == "0" {
		interval = extractXMLTag(decrypted, "keep-retry")
	}
	seconds, err := strconv.Atoi(interval)
	if err != nil || seconds < 1 || seconds > 3600 {
		return fmt.Errorf("invalid heartbeat interval")
	}
	c.keepRetry = interval
	return nil
}

func (c *Client) Term() {
	if c.termURL == "" {
		return
	}
	curTime := time.Now().Format("2006-01-02 15:04:05")
	payload := fmt.Sprintf(
		`<?xml version="1.0" encoding="utf-8"?>
<request>
    <user-agent>%s</user-agent>
    <client-id>%s</client-id>
    <local-time>%s</local-time>
    <host-name>%s</host-name>
    <ipv4>%s</ipv4>
    <ticket>%s</ticket>
    <ipv6></ipv6>
    <mac>%s</mac>
    <ostag>%s</ostag>
</request>
`,
		UserAgent,
		c.states.GetClientID(),
		curTime,
		HostName,
		c.states.GetUserIP(),
		c.states.GetTicket(),
		c.states.GetMacAddress(),
		HostName,
	)
	encrypted, err := c.session.Encrypt(payload)
	if err != nil {
		return
	}
	_, _ = network.Post(c.httpClient, c.termURL, encrypted, c.states, nil)
	log.Printf("[Client] Terminated.")
}

// extractXMLTag is a simple XML tag value extractor that also strips CDATA wrappers.
func extractXMLTag(xml, tag string) string {
	startTag := "<" + tag + ">"
	endTag := "</" + tag + ">"
	start := strings.Index(xml, startTag)
	if start == -1 {
		return ""
	}
	start += len(startTag)
	end := strings.Index(xml[start:], endTag)
	if end == -1 {
		return ""
	}
	val := xml[start : start+end]
	// Strip CDATA wrapper if present
	const cdataPrefix = "<![CDATA["
	const cdataSuffix = "]]>"
	if strings.HasPrefix(val, cdataPrefix) && strings.HasSuffix(val, cdataSuffix) {
		val = val[len(cdataPrefix) : len(val)-len(cdataSuffix)]
	}
	return val
}
