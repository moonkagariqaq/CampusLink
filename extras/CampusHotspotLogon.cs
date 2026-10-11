using System;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Net.NetworkInformation;
using System.Threading;
using System.Web.Script.Serialization;
using Windows.Networking.Connectivity;
using Windows.Networking.NetworkOperators;

// Runs in the signed-in user's session, independently of CampusLink's service.
internal static class CampusHotspotLogon {
    static readonly string Folder=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"CampusLink","Hotspot");
    static void Report(string state,string message){Directory.CreateDirectory(Folder);File.WriteAllText(Path.Combine(Folder,"status.json"),new JavaScriptSerializer().Serialize(new {Time=DateTime.Now.ToString("s"),State=state,Message=message}));}
    [STAThread] static int Main(string[] args){
        bool created;
        using(var mutex=new Mutex(true,"Local\\CampusLink.HotspotLogon",out created)){
            if(!created)return 0;
            try{
                if(args.Contains("--probe")){Report("probe",Manager().TetheringOperationalState.ToString());return 0;}
                var deadline=DateTime.UtcNow.AddMinutes(4);Report("waiting","Waiting for campus authentication");
                while(DateTime.UtcNow<deadline){
                    try{
                        var manager=Manager();
                        if(manager.TetheringOperationalState==TetheringOperationalState.On){Report("on","Hotspot is already on");return 0;}
                        if(!Online()){Thread.Sleep(5000);continue;}
                        var operation=manager.StartTetheringAsync();
                        var waitUntil=DateTime.UtcNow.AddSeconds(30);
                        while(operation.Status==Windows.Foundation.AsyncStatus.Started&&DateTime.UtcNow<waitUntil)Thread.Sleep(100);
                        if(operation.Status==Windows.Foundation.AsyncStatus.Started){operation.Cancel();operation.Close();throw new TimeoutException("Hotspot startup timed out");}
                        NetworkOperatorTetheringOperationResult result;
                        try{result=operation.GetResults();}finally{operation.Close();}
                        if(result.Status==TetheringOperationStatus.Success&&manager.TetheringOperationalState==TetheringOperationalState.On){Report("on","Hotspot started after campus authentication");return 0;}
                        Report("retry","Windows hotspot result: "+result.Status);
                    }catch(Exception e){Report("retry",e.Message);}
                    Thread.Sleep(10000);
                }
                Report("error","Hotspot startup did not complete within four minutes");return 1;
            }catch(Exception e){Report("error",e.Message);return 1;}
        }
    }
    static NetworkOperatorTetheringManager Manager(){
        var nic=NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n=>n.OperationalStatus==OperationalStatus.Up&&n.GetIPProperties().UnicastAddresses.Any(a=>a.Address.ToString().StartsWith("100.2.")));
        if(nic==null)throw new InvalidOperationException("Campus Ethernet is not ready");
        Guid id=Guid.Parse(nic.Id);
        var profile=NetworkInformation.GetConnectionProfiles().FirstOrDefault(p=>p.NetworkAdapter!=null&&p.NetworkAdapter.NetworkAdapterId==id);
        if(profile==null)throw new InvalidOperationException("Campus connection profile is not ready");
        return NetworkOperatorTetheringManager.CreateFromConnectionProfile(profile);
    }
    static bool Online(){
        using(var pipe=new NamedPipeClientStream(".","CampusLink.Control.v2",PipeDirection.InOut)){
            try{pipe.Connect(1200);using(var writer=new StreamWriter(pipe,new System.Text.UTF8Encoding(false),1024,true)){writer.AutoFlush=true;using(var reader=new StreamReader(pipe,System.Text.Encoding.UTF8,false,4096,true)){writer.WriteLine("status");var read=reader.ReadLineAsync();if(!read.Wait(2000))return false;var state=new JavaScriptSerializer().Deserialize<System.Collections.Generic.Dictionary<string,object>>(read.Result);return (string)state["State"]=="online";}}}catch{return false;}
        }
    }
}
