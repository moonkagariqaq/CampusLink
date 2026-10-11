using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using Microsoft.Win32;

// UI, settings, Windows service and authentication supervision are separate.
internal static class App {
    internal const string ServiceName="CampusLinkAuto", PipeName="CampusLink.Control.v2";
    internal static readonly string Root=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"CampusLink");
    internal static readonly string Bin=Path.Combine(Root,"bin"), Data=Path.Combine(Root,"data");
    internal static readonly JavaScriptSerializer Json=new JavaScriptSerializer();
    [STAThread] static void Main(string[] args) {
        if(args.Length>0 && args[0]=="--service") {ServiceBase.Run(new CampusService());return;}
        if(args.Length==2 && args[0]=="--install-auto") {try {Installer.Install(args[1]);Environment.ExitCode=0;}catch(Exception e){Environment.ExitCode=1;MessageBox.Show("后台安装未完成："+e.Message,"校园连接");}return;}
        if(args.Length==1 && args[0]=="--remove-auto") {try {Installer.Remove();Environment.ExitCode=0;}catch {Environment.ExitCode=1;MessageBox.Show("无法移除后台服务，请以管理员身份执行。","校园连接");}return;}
        if(args.Length==1 && args[0]=="--self-test") {SelfTest();return;}
        Settings incoming=null;
        if(args.Length==1 && args[0]=="--configure-stdin") {incoming=Json.Deserialize<Settings>(Console.ReadLine());}
        bool created;
        using(var mutex=new Mutex(true,"Local\\CampusLink.UI.v2."+WindowsIdentity.GetCurrent().User.Value,out created)) {
            if(!created)return;
            Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainWindow(incoming));
        }
    }
    internal static bool Installed {get {try {return ServiceController.GetServices().Any(s=>s.ServiceName==ServiceName);}catch{return false;}}}
    internal static string ExtractCore(string directory) {
        byte[] bytes;
        using(var s=Assembly.GetExecutingAssembly().GetManifestResourceStream("campus-core"))
        using(var m=new MemoryStream()){if(s==null)throw new IOException("认证模块缺失");s.CopyTo(m);bytes=m.ToArray();}
        Directory.CreateDirectory(directory);
        string hash;using(var sha=SHA256.Create())hash=BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-","");
        string path=Path.Combine(directory,"campus-core.exe");bool good=false;
        if(File.Exists(path))using(var sha=SHA256.Create())using(var f=File.OpenRead(path))good=BitConverter.ToString(sha.ComputeHash(f)).Replace("-","")==hash;
        if(!good)File.WriteAllBytes(path,bytes);
        return path;
    }
    internal static async Task<bool> InstallFromUI(Settings settings) {
        string folder=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"CampusLink");Directory.CreateDirectory(folder);
        string bootstrap=Path.Combine(folder,"setup-"+Guid.NewGuid().ToString("N")+".dat");
        settings.OwnerSid=WindowsIdentity.GetCurrent().User.Value;
        File.WriteAllBytes(bootstrap,ProtectedData.Protect(Encoding.UTF8.GetBytes(Json.Serialize(settings)),null,DataProtectionScope.CurrentUser));
        try {
            var p=Process.Start(new ProcessStartInfo(Assembly.GetExecutingAssembly().Location,"--install-auto \""+bootstrap+"\""){UseShellExecute=true,Verb="runas",WindowStyle=ProcessWindowStyle.Hidden});
            await Task.Run(()=>p.WaitForExit());int code=p.ExitCode;p.Dispose();return code==0;
        }catch(Win32Exception){return false;}finally{if(File.Exists(bootstrap))File.Delete(bootstrap);}
    }
    static void SelfTest() {
        var s=new Settings {User="unit-test-user",Password="not-a-real-password",Remember=true};
        byte[] encrypted=ProtectedData.Protect(Encoding.UTF8.GetBytes(Json.Serialize(s)),null,DataProtectionScope.CurrentUser);
        if(Encoding.UTF8.GetString(encrypted).Contains(s.Password))throw new Exception("Plaintext credential leak");
        var restored=Json.Deserialize<Settings>(Encoding.UTF8.GetString(ProtectedData.Unprotect(encrypted,null,DataProtectionScope.CurrentUser)));
        if(restored.Password!=s.Password)throw new Exception("Credential round trip failed");
        if(Adapter.Pick(new Settings())==null)throw new Exception("No physical adapter available");
        Console.WriteLine("DPAPI round trip and automatic physical adapter selection: PASS");
    }
}

internal sealed class Settings {
    public string User="",Password="",Network="",Portal="http://121.8.177.212:7001/index.cgi",OwnerSid="";
    public bool Remember=true,Automatic=true;
}
internal static class Store {
    static string LocalFile {get{return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"CampusLink","settings.dat");}}
    internal static string MachineFile {get{return Path.Combine(App.Data,"settings.dat");}}
    internal static Settings Read(bool machineOnly=false) {
        string path=machineOnly||File.Exists(MachineFile)?MachineFile:LocalFile;
        if(!File.Exists(path))return new Settings();
        byte[] bytes=File.ReadAllBytes(path);
        var scope=path==MachineFile?DataProtectionScope.LocalMachine:DataProtectionScope.CurrentUser;
        var result=App.Json.Deserialize<Settings>(Encoding.UTF8.GetString(ProtectedData.Unprotect(bytes,null,scope)));
        return result??new Settings();
    }
    internal static void Save(Settings settings,bool machine=false) {
        string path=machine||File.Exists(MachineFile)?MachineFile:LocalFile;
        Directory.CreateDirectory(Path.GetDirectoryName(path));
        var copy=new Settings {User=settings.Remember?settings.User:"",Password=settings.Remember?settings.Password:"",Remember=settings.Remember,Automatic=settings.Automatic&&settings.Remember,Network=settings.Network,Portal=settings.Portal,OwnerSid=settings.OwnerSid};
        byte[] encrypted=ProtectedData.Protect(Encoding.UTF8.GetBytes(App.Json.Serialize(copy)),null,path==MachineFile?DataProtectionScope.LocalMachine:DataProtectionScope.CurrentUser);
        string temp=path+"."+Guid.NewGuid().ToString("N")+".tmp";
        File.WriteAllBytes(temp,encrypted);
        if(File.Exists(path))File.Replace(temp,path,null);else File.Move(temp,path);
    }
}
internal sealed class Adapter {
    public string Name,IP,DNS;
    public override string ToString(){return Name+" · "+IP;}
    internal static List<Adapter> List() {
        var result=new List<Adapter>();
        foreach(var n in NetworkInterface.GetAllNetworkInterfaces()) {
            if(n.OperationalStatus!=OperationalStatus.Up||n.NetworkInterfaceType==NetworkInterfaceType.Loopback||n.NetworkInterfaceType==NetworkInterfaceType.Tunnel)continue;
            string description=(n.Name+" "+n.Description).ToLowerInvariant();
            if(new[]{"wintun","mihomo","clash","wi-fi direct","virtual","虚拟","meta","tap-windows"}.Any(description.Contains))continue;
            var p=n.GetIPProperties();var ip=p.UnicastAddresses.FirstOrDefault(a=>a.Address.AddressFamily==AddressFamily.InterNetwork&&!a.Address.ToString().StartsWith("169.254."));if(ip==null)continue;
            var dns=p.DnsAddresses.FirstOrDefault(a=>a.AddressFamily==AddressFamily.InterNetwork);
            result.Add(new Adapter{Name=n.Name,IP=ip.Address.ToString(),DNS=dns==null?"202.96.128.86":dns.ToString()});
        }
        return result;
    }
    internal static Adapter Pick(Settings s) {
        var list=List();if(s.Network.Length>0)return list.FirstOrDefault(n=>n.Name==s.Network);
        return list.FirstOrDefault(n=>n.IP.StartsWith("100.2."))??list.FirstOrDefault();
    }
}
internal sealed class Snapshot {
    public bool Running,Desired,Installed;
    public string State="idle",Message="尚未连接",Network="";
    public string[] Logs=new string[0];
}
internal sealed class AuthEngine : IDisposable {
    readonly object gate=new object();readonly List<string> logs=new List<string>();
    readonly bool machine;readonly string corePath;
    volatile bool quit,desired,restart;Process process;StreamWriter input;Thread worker;Settings sessionSettings,activeSettings;readonly IntPtr job;
    string state="idle",message="尚未连接",network="";
    internal AuthEngine(bool serviceMode) {
        machine=serviceMode;
        job=ChildJob.Create();
        corePath=serviceMode?Path.Combine(App.Bin,"campus-core.exe"):App.ExtractCore(Path.Combine(Path.GetTempPath(),"CampusLink-v2",Assembly.GetExecutingAssembly().ManifestModule.ModuleVersionId.ToString()));
    }
    internal void Start() {desired=machine&&Store.Read(true).Automatic;worker=new Thread(Loop){IsBackground=true};worker.Start();}
    internal void Connect(Settings settings=null){lock(gate){bool wasDesired=desired;bool changed=settings!=null&&(activeSettings==null||settings.User!=activeSettings.User||settings.Password!=activeSettings.Password||settings.Network!=activeSettings.Network||settings.Portal!=activeSettings.Portal);if(settings!=null)sessionSettings=settings;desired=true;if(process!=null&&(!wasDesired||changed))restart=true;}}
    internal void Disconnect(){desired=false;SignalStop();Set("idle","已断开");}
    internal Snapshot Read(){lock(gate)return new Snapshot {Running=process!=null,Desired=desired,Installed=machine,State=state,Message=message,Network=network,Logs=logs.ToArray()};}
    void Set(string kind,string text){lock(gate){state=kind;message=text;if(logs.Count==0||!logs[logs.Count-1].EndsWith(text)){logs.Add(DateTime.Now.ToString("HH:mm:ss")+"  "+text);if(logs.Count>120)logs.RemoveAt(0);}}}
    void SignalStop(){lock(gate){try{if(input!=null)input.WriteLine("{\"action\":\"stop\"}");}catch{}}}
    void Loop() {
        while(!quit) {
            if(!desired){Thread.Sleep(500);continue;}
            Settings s;Adapter adapter;
            try{lock(gate)s=sessionSettings;s=s??Store.Read(machine);adapter=Adapter.Pick(s);}catch{Set("error","读取本机配置失败");Pause(10);continue;}
            if(s.User.Length==0||s.Password.Length==0){desired=false;Set("idle","请先保存账号和密码");continue;}
            if(adapter==null){Set("waiting","等待校园网网卡就绪…");Pause(2);continue;}
            restart=false;bool loginRejected=false;
            Process p=null;
            try {
                Set("connecting","正在连接校园网…");lock(gate)network=adapter.Name;
                p=new Process {StartInfo=new ProcessStartInfo(corePath) {UseShellExecute=false,CreateNoWindow=true,RedirectStandardInput=true,RedirectStandardOutput=true,RedirectStandardError=true,StandardOutputEncoding=Encoding.UTF8,StandardErrorEncoding=Encoding.UTF8}};
                p.OutputDataReceived+=delegate(object sender,DataReceivedEventArgs e){if(e.Data==null)return;try{
                    var item=new JavaScriptSerializer().Deserialize<Dictionary<string,string>>(e.Data);string type=item["type"],text=item["message"];
                    if(type=="online"||type=="heartbeat")Set("online","已连接校园网");
                    else if(type=="error"){Set("error",text);if(text.StartsWith("登录失败"))loginRejected=true;}
                    else if(type=="status"&&Read().State!="online")Set("connecting",text);
                }catch{}};
                p.ErrorDataReceived+=delegate(object sender,DataReceivedEventArgs e){if(e.Data!=null)Set("error","认证模块异常，稍后重试");};
                p.Start();
                ChildJob.Assign(job,p.Handle);
                lock(gate){process=p;activeSettings=s;input=new StreamWriter(p.StandardInput.BaseStream,new UTF8Encoding(false),1024,true){AutoFlush=true};
                    input.WriteLine(new JavaScriptSerializer().Serialize(new Dictionary<string,object>{{"action","start"},{"user",s.User},{"password",s.Password},{"interface",adapter.Name},{"dns",adapter.DNS},{"portal",s.Portal}}));}
                p.BeginOutputReadLine();p.BeginErrorReadLine();
                while(!p.WaitForExit(500)){if(quit||!desired||restart){SignalStop();if(!p.WaitForExit(25000))p.Kill();break;}}
                p.WaitForExit();
            }catch{Set("error","连接暂不可用，正在等待网络恢复");}
            finally {lock(gate){try{if(p!=null&&!p.HasExited)p.Kill();}catch{}process=null;input=null;}if(p!=null)p.Dispose();}
            if(loginRejected){desired=false;Set("error","登录未通过，请检查账号和密码");}
            if(desired&&!quit){Set("waiting","连接中断，稍后自动重试…");Pause(restart?1:30);}
        }
    }
    void Pause(int seconds){for(int i=0;i<seconds*10&&!quit&&desired;i++)Thread.Sleep(100);}
    public void Dispose(){quit=true;desired=false;SignalStop();if(worker!=null&&!worker.Join(30000)){lock(gate){try{if(process!=null)process.Kill();}catch{}}}ChildJob.Close(job);}
}

internal sealed class CampusService : ServiceBase {
    AuthEngine engine;Thread server;volatile bool quit;
    public CampusService(){ServiceName=App.ServiceName;CanStop=true;CanShutdown=true;AutoLog=false;}
    protected override void OnStart(string[] args){engine=new AuthEngine(true);engine.Start();server=new Thread(Serve){IsBackground=true};server.Start();}
    void Serve() {
        string owner=File.ReadAllText(Path.Combine(App.Bin,"owner.sid")).Trim();
        while(!quit) {
            try {
                var security=new PipeSecurity();security.SetAccessRuleProtection(true,false);
                foreach(var sid in new[]{"S-1-5-19","S-1-5-18","S-1-5-32-544"})security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(sid),PipeAccessRights.FullControl,AccessControlType.Allow));
                security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(owner),PipeAccessRights.ReadWrite,AccessControlType.Allow));
                using(var pipe=new NamedPipeServerStream(App.PipeName,PipeDirection.InOut,1,PipeTransmissionMode.Byte,PipeOptions.Asynchronous,65536,65536,security)) {
                    var connection=pipe.BeginWaitForConnection(null,null);
                    using(var ready=connection.AsyncWaitHandle){while(!quit&&!ready.WaitOne(250)){}if(quit)break;pipe.EndWaitForConnection(connection);}
                    using(var reader=new StreamReader(pipe,new UTF8Encoding(false),false,4096,true))
                    using(var writer=new StreamWriter(pipe,new UTF8Encoding(false),4096,true){AutoFlush=true}) {
                        var read=reader.ReadLineAsync();if(!read.Wait(3000))continue;string command=read.Result;
                        if(command!=null&&command.StartsWith("{")){var request=new JavaScriptSerializer().Deserialize<ConnectRequest>(command);if(request.Action=="connect")engine.Connect(request.Settings);}
                        else if(command=="connect")engine.Connect();else if(command=="disconnect")engine.Disconnect();
                        writer.WriteLine(new JavaScriptSerializer().Serialize(engine.Read()));
                    }
                }
            }catch{if(!quit)Thread.Sleep(500);}
        }
    }
    protected override void OnStop(){RequestAdditionalTime(35000);quit=true;if(engine!=null)engine.Dispose();if(server!=null)server.Join(2000);}
    protected override void OnShutdown(){OnStop();}
}
internal static class ChildJob {
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode)]static extern IntPtr CreateJobObject(IntPtr security,string name);
    [DllImport("kernel32.dll")]static extern bool SetInformationJobObject(IntPtr job,int kind,IntPtr information,uint length);
    [DllImport("kernel32.dll")]static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
    [DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr handle);
    internal static IntPtr Create(){var handle=CreateJobObject(IntPtr.Zero,null);if(handle==IntPtr.Zero)return handle;int size=IntPtr.Size==8?144:112;var data=Marshal.AllocHGlobal(size);try{for(int i=0;i<size;i++)Marshal.WriteByte(data,i,0);Marshal.WriteInt32(data,16,0x2000);if(!SetInformationJobObject(handle,9,data,(uint)size)){CloseHandle(handle);return IntPtr.Zero;}return handle;}finally{Marshal.FreeHGlobal(data);}}
    internal static void Assign(IntPtr job,IntPtr process){if(job!=IntPtr.Zero)AssignProcessToJobObject(job,process);}
    internal static void Close(IntPtr job){if(job!=IntPtr.Zero)CloseHandle(job);}
}
internal static class ControlClient {
    internal static Snapshot Send(string action,Settings settings=null) {
        using(var pipe=new NamedPipeClientStream(".",App.PipeName,PipeDirection.InOut,PipeOptions.None)) {
            pipe.Connect(1200);
            using(var writer=new StreamWriter(pipe,new UTF8Encoding(false),4096,true){AutoFlush=true})
            using(var reader=new StreamReader(pipe,new UTF8Encoding(false),false,4096,true)) {writer.WriteLine(settings==null?action:new JavaScriptSerializer().Serialize(new ConnectRequest{Action=action,Settings=settings}));var read=reader.ReadLineAsync();if(!read.Wait(2000))throw new System.TimeoutException();return new JavaScriptSerializer().Deserialize<Snapshot>(read.Result);}
        }
    }
}
internal sealed class ConnectRequest {public string Action;public Settings Settings;}

internal static class Installer {
    internal static void Install(string bootstrap) {
        var s=App.Json.Deserialize<Settings>(Encoding.UTF8.GetString(ProtectedData.Unprotect(File.ReadAllBytes(bootstrap),null,DataProtectionScope.CurrentUser)));
        if(s.OwnerSid!=WindowsIdentity.GetCurrent().User.Value)throw new InvalidOperationException("请使用当前账号的管理员权限确认");
        StopOwn();
        SecureDirectory(App.Root,s.OwnerSid,false);SecureDirectory(App.Bin,s.OwnerSid,false);SecureDirectory(App.Data,s.OwnerSid,true);
        string exe=Path.Combine(App.Bin,"CampusLink.exe");File.Copy(Assembly.GetExecutingAssembly().Location,exe,true);App.ExtractCore(App.Bin);
        File.WriteAllText(Path.Combine(App.Bin,"owner.sid"),s.OwnerSid,Encoding.ASCII);
        int previous=2;string rollback=Path.Combine(App.Bin,"original-service-start.txt");
        if(File.Exists(rollback))Int32.TryParse(File.ReadAllText(rollback),out previous);
        else {using(var key=Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Services\\ESurfingSvr")){if(key!=null)previous=Convert.ToInt32(key.GetValue("Start",2));}File.WriteAllText(rollback,previous.ToString());}
        Store.Save(s,true);
        try {
            foreach(var p in Process.GetProcessesByName("ESurfingClient")){try{p.Kill();p.WaitForExit(3000);}catch{}p.Dispose();}
            try{using(var old=new ServiceController("ESurfingSvr")){if(old.Status!=ServiceControllerStatus.Stopped){old.Stop();old.WaitForStatus(ServiceControllerStatus.Stopped,TimeSpan.FromSeconds(20));}}}catch{}
            Native.SetStartup("ESurfingSvr",3);
            Native.Install(exe);
            using(var service=new ServiceController(App.ServiceName)){service.Start();service.WaitForStatus(ServiceControllerStatus.Running,TimeSpan.FromSeconds(20));}
        }catch{Native.SetStartup("ESurfingSvr",(uint)previous);throw;}
    }
    internal static void SecureDirectory(string path,string owner,bool writable) {
        Directory.CreateDirectory(path);var acl=new DirectorySecurity();acl.SetAccessRuleProtection(true,false);
        var inherit=InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit;
        foreach(var sid in new[]{"S-1-5-18","S-1-5-32-544"})acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid),FileSystemRights.FullControl,inherit,PropagationFlags.None,AccessControlType.Allow));
        acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier("S-1-5-19"),FileSystemRights.ReadAndExecute,inherit,PropagationFlags.None,AccessControlType.Allow));
        acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(owner),writable?FileSystemRights.Modify:FileSystemRights.ReadAndExecute,inherit,PropagationFlags.None,AccessControlType.Allow));
        new DirectoryInfo(path).SetAccessControl(acl);
    }
    static void StopOwn(){try{using(var s=new ServiceController(App.ServiceName)){if(s.Status!=ServiceControllerStatus.Stopped){s.Stop();s.WaitForStatus(ServiceControllerStatus.Stopped,TimeSpan.FromSeconds(35));}}}catch(InvalidOperationException){}}
    internal static void Remove(){StopOwn();Native.Remove();int old=2;string path=Path.Combine(App.Bin,"original-service-start.txt");if(File.Exists(path))Int32.TryParse(File.ReadAllText(path),out old);Native.SetStartup("ESurfingSvr",(uint)old);}
}
internal static class Native {
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr OpenSCManager(string machine,string database,uint access);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr OpenService(IntPtr manager,string name,uint access);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr CreateService(IntPtr manager,string name,string display,uint access,uint type,uint start,uint error,string binary,string group,IntPtr tag,string dependencies,string account,string password);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool ChangeServiceConfig(IntPtr service,uint type,uint start,uint error,string binary,string group,IntPtr tag,string dependencies,string account,string password,string display);
    [DllImport("advapi32.dll",SetLastError=true)]static extern bool DeleteService(IntPtr service);
    [DllImport("advapi32.dll")]static extern bool CloseServiceHandle(IntPtr handle);
    internal static void Install(string exe) {
        var manager=OpenSCManager(null,null,3);if(manager==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
        IntPtr service=IntPtr.Zero;
        try{string binary="\""+exe+"\" --service";service=OpenService(manager,App.ServiceName,0xF01FF);
            if(service==IntPtr.Zero)service=CreateService(manager,App.ServiceName,"CampusLink 校园网自动连接",0xF01FF,0x10,2,1,binary,null,IntPtr.Zero,"Tcpip\0\0","NT AUTHORITY\\LocalService",null);
            else if(!ChangeServiceConfig(service,0xffffffff,2,1,binary,null,IntPtr.Zero,"Tcpip\0\0","NT AUTHORITY\\LocalService",null,null))throw new Win32Exception(Marshal.GetLastWin32Error());
            if(service==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());
        }finally{if(service!=IntPtr.Zero)CloseServiceHandle(service);CloseServiceHandle(manager);}
    }
    internal static void SetStartup(string name,uint mode){var manager=OpenSCManager(null,null,1);if(manager==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());var service=OpenService(manager,name,2);try{if(service==IntPtr.Zero){if(Marshal.GetLastWin32Error()==1060)return;throw new Win32Exception(Marshal.GetLastWin32Error());}if(!ChangeServiceConfig(service,0xffffffff,mode,0xffffffff,null,null,IntPtr.Zero,null,null,null,null))throw new Win32Exception(Marshal.GetLastWin32Error());}finally{if(service!=IntPtr.Zero)CloseServiceHandle(service);CloseServiceHandle(manager);}}
    internal static void Remove(){var manager=OpenSCManager(null,null,1);var service=OpenService(manager,App.ServiceName,0x10000);try{if(service!=IntPtr.Zero&&!DeleteService(service))throw new Win32Exception(Marshal.GetLastWin32Error());}finally{if(service!=IntPtr.Zero)CloseServiceHandle(service);if(manager!=IntPtr.Zero)CloseServiceHandle(manager);}}
}

internal sealed class MainWindow : Form {
    readonly TextBox user=new TextBox(),pass=new TextBox();readonly CheckBox remember=new CheckBox(),automatic=new CheckBox();
    readonly Label status=new Label(),detail=new Label();readonly Button primary=new Button();readonly NotifyIcon tray=new NotifyIcon();
    Settings settings;AuthEngine local;Snapshot snapshot=new Snapshot();readonly System.Windows.Forms.Timer timer=new System.Windows.Forms.Timer();bool busy,polling,exit,initialized;
    internal MainWindow(Settings incoming) {
        Text="CampusLink · 校园连接";ClientSize=new Size(400,345);FormBorderStyle=FormBorderStyle.FixedSingle;MaximizeBox=false;StartPosition=FormStartPosition.CenterScreen;BackColor=Color.White;Font=new Font("Microsoft YaHei UI",10);AutoScaleMode=AutoScaleMode.Dpi;
        Controls.Add(new Label {Text="校园连接",Font=new Font(Font.FontFamily,21,FontStyle.Bold),Location=new Point(25,21),AutoSize=true});
        var more=new Button{Text="⋯",Location=new Point(344,23),Size=new Size(32,32),FlatStyle=FlatStyle.Flat};more.FlatAppearance.BorderSize=0;more.Click+=delegate {Advanced();};Controls.Add(more);
        status.SetBounds(27,77,345,24);status.ForeColor=Color.FromArgb(33,127,81);Controls.Add(status);
        AddField("账号",user,113);AddField("密码",pass,173);pass.UseSystemPasswordChar=true;
        remember.Text="记住账号密码";remember.SetBounds(27,237,170,25);automatic.Text="开机自动连接";automatic.SetBounds(207,237,172,25);Controls.Add(remember);Controls.Add(automatic);
        remember.CheckedChanged+=delegate {automatic.Enabled=remember.Checked;if(!remember.Checked)automatic.Checked=false;};
        primary.SetBounds(27,278,346,40);primary.FlatStyle=FlatStyle.Flat;primary.FlatAppearance.BorderSize=0;primary.BackColor=Color.FromArgb(38,105,204);primary.ForeColor=Color.White;primary.Click+=async delegate {await Toggle();};Controls.Add(primary);
        detail.SetBounds(27,324,346,18);detail.Font=new Font(Font.FontFamily,8);detail.ForeColor=Color.Gray;Controls.Add(detail);
        settings=incoming??Store.Read();Fill();
        initialized=true;
        remember.CheckedChanged+=async delegate {await PreferencesChanged();};automatic.CheckedChanged+=async delegate {await PreferencesChanged();};
        tray.Icon=SystemIcons.Application;tray.Text="CampusLink 校园连接";tray.Visible=true;tray.DoubleClick+=delegate{ShowWindow();};
        var menu=new ContextMenuStrip();menu.Items.Add("显示窗口",null,delegate{ShowWindow();});menu.Items.Add("断开连接",null,async delegate{await Command("disconnect");});menu.Items.Add("退出界面",null,delegate{exit=true;Close();});tray.ContextMenuStrip=menu;
        FormClosing+=delegate(object s,FormClosingEventArgs e){if(!exit){e.Cancel=true;Hide();}else{timer.Stop();tray.Dispose();if(local!=null)local.Dispose();}};
        timer.Interval=1500;timer.Tick+=async delegate{await Poll();};
        Shown+=async delegate{timer.Start();await Poll();if(incoming!=null){await SaveAndConnect();incoming=null;}else if(!App.Installed&&settings.Automatic&&settings.User.Length>0){await SaveAndConnect();}};
    }
    void AddField(string title,TextBox box,int y){Controls.Add(new Label {Text=title,Location=new Point(27,y),AutoSize=true,ForeColor=Color.DimGray,Font=new Font(Font.FontFamily,9)});box.SetBounds(27,y+22,346,29);box.BorderStyle=BorderStyle.FixedSingle;Controls.Add(box);}
    void Fill(){user.Text=settings.User;pass.Text=settings.Password;remember.Checked=settings.Remember;automatic.Checked=settings.Automatic&&settings.Remember;primary.Text="连接校园网";status.Text="尚未连接";}
    void ReadFields(){settings.User=user.Text.Trim();settings.Password=pass.Text;settings.Remember=remember.Checked;settings.Automatic=automatic.Checked&&remember.Checked;settings.OwnerSid=WindowsIdentity.GetCurrent().User.Value;}
    async Task Poll(){if(polling||busy)return;polling=true;try{snapshot=App.Installed?await Task.Run(()=>ControlClient.Send("status")):(local==null?new Snapshot():local.Read());Render();}catch{status.Text="后台服务正在启动…";}finally{polling=false;}}
    void Render(){bool online=snapshot.State=="online";status.Text=online?"●  已连接校园网":snapshot.Message;status.ForeColor=online?Color.FromArgb(33,127,81):(snapshot.State=="error"?Color.Firebrick:Color.DimGray);primary.Text=snapshot.Desired?"断开连接":"连接校园网";detail.Text=snapshot.Installed?"后台连接运行中 · 关闭窗口不会断网":"连接就绪";}
    async Task Command(string command){if(App.Installed)snapshot=await Task.Run(()=>ControlClient.Send(command,command=="connect"?settings:null));else{if(local==null){local=new AuthEngine(false);local.Start();}if(command=="connect")local.Connect(settings);else local.Disconnect();snapshot=local.Read();}Render();}
    async Task Toggle(){if(busy)return;if(snapshot.Desired){await Command("disconnect");return;}await SaveAndConnect();}
    async Task SaveAndConnect(){
        if(busy)return;ReadFields();if(settings.User.Length==0||settings.Password.Length==0){status.Text="请填写账号和密码";return;}busy=true;primary.Enabled=false;
        try{
            if(settings.Automatic&&!App.Installed){status.Text="正在启用开机前自动连接…";if(!await App.InstallFromUI(settings)){status.Text="后台安装未完成，可以稍后重试";return;}}
            else Store.Save(settings);
            await Command("connect");
        }catch{status.Text="设置或连接未完成，请重试";}finally{busy=false;primary.Enabled=true;}
    }
    async Task PreferencesChanged(){if(!initialized||busy)return;ReadFields();try{if(settings.Automatic&&!App.Installed&&settings.User.Length>0&&settings.Password.Length>0){busy=true;if(!await App.InstallFromUI(settings))status.Text="开机后台未启用";}else Store.Save(settings);}catch{status.Text="设置未保存，请重试";}finally{busy=false;}}
    void ShowWindow(){Show();WindowState=FormWindowState.Normal;Activate();}
    void Advanced(){
        using(var dialog=new Form{Text="高级设置",ClientSize=new Size(450,390),StartPosition=FormStartPosition.CenterParent,Font=Font,BackColor=Color.White,FormBorderStyle=FormBorderStyle.FixedDialog,MaximizeBox=false,MinimizeBox=false}){
            var network=new ComboBox{DropDownStyle=ComboBoxStyle.DropDownList,Location=new Point(20,45),Size=new Size(410,30)};network.Items.Add("自动选择（推荐）");foreach(var item in Adapter.List())network.Items.Add(item);network.SelectedIndex=0;for(int i=1;i<network.Items.Count;i++)if(((Adapter)network.Items[i]).Name==settings.Network)network.SelectedIndex=i;
            dialog.Controls.Add(new Label{Text="校园网网卡",Location=new Point(20,18),AutoSize=true});dialog.Controls.Add(network);
            var entry=new TextBox{Text=settings.Portal,Location=new Point(20,112),Size=new Size(410,30)};dialog.Controls.Add(new Label{Text="认证入口",Location=new Point(20,85),AutoSize=true});dialog.Controls.Add(entry);
            var logs=new TextBox{Multiline=true,ReadOnly=true,ScrollBars=ScrollBars.Vertical,Location=new Point(20,166),Size=new Size(410,155),Text=String.Join(Environment.NewLine,snapshot.Logs)};dialog.Controls.Add(logs);
            var save=new Button{Text="保存设置",Location=new Point(295,339),Size=new Size(135,34)};save.Click+=delegate{Uri uri;if(!Uri.TryCreate(entry.Text,UriKind.Absolute,out uri)||(uri.Scheme!="http"&&uri.Scheme!="https")||uri.UserInfo.Length>0){MessageBox.Show("认证入口地址无效");return;}settings.Network=network.SelectedIndex==0?"":((Adapter)network.SelectedItem).Name;settings.Portal=entry.Text;ReadFields();Store.Save(settings);dialog.Close();};dialog.Controls.Add(save);
            var remove=new Button{Text="移除开机后台",Location=new Point(20,339),Size=new Size(155,34)};remove.Enabled=App.Installed;remove.Click+=async delegate{try{var p=Process.Start(new ProcessStartInfo(Assembly.GetExecutingAssembly().Location,"--remove-auto"){UseShellExecute=true,Verb="runas",WindowStyle=ProcessWindowStyle.Hidden});await Task.Run(()=>p.WaitForExit());if(p.ExitCode==0){automatic.Checked=false;settings.Automatic=false;Store.Save(settings);dialog.Close();}p.Dispose();}catch{}};dialog.Controls.Add(remove);
            dialog.ShowDialog(this);
        }
    }
}
