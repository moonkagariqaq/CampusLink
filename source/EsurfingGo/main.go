package main

import (
	"bufio"
	"encoding/json"
	"esurfing/network"
	"flag"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Credentials arrive only through inherited stdin, never process arguments.
type PipeCommand struct {
	Action    string `json:"action"`
	User      string `json:"user"`
	Password  string `json:"password"`
	Interface string `json:"interface"`
	DNS       string `json:"dns"`
	Portal    string `json:"portal"`
	Code      string `json:"code"`
}

var eventMu sync.Mutex

func report(kind, message string) {
	eventMu.Lock()
	defer eventMu.Unlock()
	_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"type": kind, "message": message, "time": time.Now().Format("15:04:05")})
}

var responseCodeRE = regexp.MustCompile(`response-code: ([0-9]{1,10})`)

func publicFailure(stage string, err error) {
	if strings.HasPrefix(err.Error(), "HTTP ") {
		report("error", stage+"失败："+err.Error())
		return
	}
	code := responseCodeRE.FindStringSubmatch(err.Error())
	if len(code) == 2 {
		report("error", stage+"失败，服务器错误码 "+code[1])
		return
	}
	if strings.Contains(err.Error(), "empty ticket") {
		report("error", stage+"失败：无法解密服务器响应。")
		return
	}
	report("error", stage+"失败；请检查网络或协议兼容性。")
}

func main() {
	defer func() {
		if recover() != nil {
			report("error", "协议解析异常，认证已停止。")
			os.Exit(2)
		}
	}()
	log.SetOutput(io.Discard)
	list := flag.Bool("list", false, "List active IPv4 interfaces as JSON")
	probe := flag.Bool("probe", false, "Discover portal without authenticating")
	flag.Parse()
	if *list {
		ifaces, err := net.Interfaces()
		if err != nil {
			report("error", "无法读取网卡")
			os.Exit(1)
		}
		rows := []map[string]interface{}{}
		for _, n := range ifaces {
			if n.Flags&net.FlagUp == 0 || n.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, _ := n.Addrs()
			for _, a := range addrs {
				ip, _, e := net.ParseCIDR(a.String())
				if e == nil && ip.To4() != nil && !ip.IsLinkLocalUnicast() {
					rows = append(rows, map[string]interface{}{"name": n.Name, "index": n.Index, "ip": ip.String()})
					break
				}
			}
		}
		_ = json.NewEncoder(os.Stdout).Encode(rows)
		return
	}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 65536)
	if !scanner.Scan() {
		report("error", "未收到本机登录信息")
		os.Exit(1)
	}
	var cfg PipeCommand
	if json.Unmarshal(scanner.Bytes(), &cfg) != nil {
		report("error", "登录信息格式错误")
		os.Exit(1)
	}
	if cfg.Interface == "" {
		report("error", "请选择校园网物理网卡")
		os.Exit(1)
	}
	if cfg.DNS == "" {
		cfg.DNS = "202.96.128.86"
	}
	if net.ParseIP(cfg.DNS) == nil {
		report("error", "DNS 地址无效")
		os.Exit(1)
	}
	iface := &NetworkInterface{Name: cfg.Interface}
	BoundDNS = cfg.DNS
	transport, err := NewBoundHTTPTransport(iface)
	if err != nil {
		report("error", "无法绑定所选物理网卡")
		os.Exit(1)
	}
	defer transport.CloseIdleConnections()
	if cfg.Portal == "" {
		cfg.Portal = "http://121.8.177.212:7001/index.cgi?wlanacip=119.146.175.80"
	}
	states := NewStates()
	states.RefreshStates()
	actualIface, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		report("error", "所选网卡已不可用")
		os.Exit(1)
	}
	states.SetMacAddress(actualIface.HardwareAddr.String())
	entry, err := url.Parse(cfg.Portal)
	if err != nil {
		report("error", "认证入口地址无效")
		os.Exit(1)
	}
	query := entry.Query()
	if query.Get("wlanuserip") == "" {
		addrs, _ := actualIface.Addrs()
		for _, a := range addrs {
			ip, _, e := net.ParseCIDR(a.String())
			if e == nil && ip.To4() != nil {
				query.Set("wlanuserip", ip.String())
				break
			}
		}
	}
	if query.Get("wlanacip") == "" && entry.Hostname() == "121.8.177.212" {
		query.Set("wlanacip", "119.146.175.80")
	}
	entry.RawQuery = query.Encode()
	if err := network.SetDetectionURL(entry.String()); err != nil {
		report("error", "认证入口地址无效")
		os.Exit(1)
	}
	if host, e := os.Hostname(); e == nil {
		HostName = host
	}
	report("status", "已绑定校园网网卡："+cfg.Interface)
	if *probe {
		result := network.DetectConfigWithClient(network.NewHTTPClient(states, transport), states, false)
		switch result.Status {
		case network.StatusRequireAuthorization:
			report("probe", "识别到天翼认证入口，协议配置可读取。")
			states.SetSchoolID(result.SchoolID)
			states.SetDomain(result.Domain)
			states.SetArea(result.Area)
			body, err := network.PostRaw(network.NewHTTPClient(states, transport), result.TicketURL, states.GetAlgoID(), states)
			if err != nil {
				report("error", "算法协商请求失败")
				return
			}
			session := NewSession()
			session.Initialize(body)
			if session.IsInitialized() {
				states.SetAlgoID(session.GetAlgoID())
				report("probe", "算法协商成功；未提交账号或密码。")
				states.SetTicketURL(result.TicketURL)
				states.SetUserIP(result.UserIP)
				states.SetAcIP(result.AcIP)
				client := NewClient(Options{}, states, session, transport)
				if _, err := client.getTicket(); err != nil {
					publicFailure("获取认证票据", err)
				} else {
					report("probe", "认证票据协商成功；未提交账号或密码。")
				}
			}
		case network.StatusSuccess:
			report("probe", "网络已联网，当前没有返回认证入口。")
		default:
			report("error", "未能识别认证入口。")
		}
		return
	}
	if strings.TrimSpace(cfg.User) == "" || cfg.Password == "" {
		report("error", "账号或密码为空")
		os.Exit(1)
	}
	smsCh := make(chan string, 1)
	stop := make(chan struct{})
	var stopOnce sync.Once
	stopFn := func() { stopOnce.Do(func() { states.SetRunning(false); close(stop) }) }
	client := NewClient(Options{LoginUser: cfg.User, LoginPassword: cfg.Password, DisableSMS: true, SMSCode: cfg.Code, SMSReader: func() string {
		report("sms", "需要短信验证码，请在窗口输入。")
		select {
		case code := <-smsCh:
			return code
		case <-stop:
			return ""
		}
	}}, states, NewSession(), transport)
	go func() {
		for scanner.Scan() {
			var cmd PipeCommand
			if json.Unmarshal(scanner.Bytes(), &cmd) != nil {
				continue
			}
			switch cmd.Action {
			case "stop":
				stopFn()
				return
			case "sms":
				select {
				case smsCh <- cmd.Code:
				default:
				}
			}
		}
		stopFn()
	}()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case <-sig:
			stopFn()
		case <-stop:
		}
	}()
	report("status", "正在认证……")
	client.Run()
	if states.IsLogged() {
		client.Term()
	}
	client.session.Free()
	report("stopped", "客户端已停止。")
}
