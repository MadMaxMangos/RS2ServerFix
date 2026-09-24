// Synthetic memory only. No game, DLL loading or live target is involved.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using RS2CountProbe;
namespace RS2CountProbeTests {
    public sealed class FakeMemory : IMemory {
        public const ulong Base=0x10000000;
        public const uint Size=0x1900000;
        readonly Dictionary<ulong,byte> bytes=new Dictionary<ulong,byte>();
        public bool ShortRead, Guarded, AliveValue=true, ChangeCounts, PendingKill, WrongClass, ChangeHeaders, ChangeTimer;
        public int GameReads,OuterReads;
        public FakeMemory() {
            Put(Base,new byte[0x500]); U16(Base,0x5A4D); U32(Base+60,0x80);
            U32(Base+0x80,0x4550);U16(Base+0x84,0x8664);U16(Base+0x86,3);U16(Base+0x94,240);
            U16(Base+0x98,0x20B);U32(Base+0xD0,Size);
            Section(0,0x1000,0x1000,0x60000000);Section(1,0x2000,0x1000,0x40000000);
            Section(2,0x1700000,0x200000,0xC0000000);
            U64(Base+0x2000,Base+0x1000);
            U64(Base+0x17950C8,0x30000000);U64(Base+0x1783E80,0x30005000);
            U64(Base+0x17981A0,0x30006000);U64(Base+0x17986E0,0x30006000);
            for(ulong p=0x30000000;p<=0x30006000;p+=0x1000){Put(p,new byte[0x800]);U64(p,Base+0x2000);}
            U64(0x30000080,0x30001000);
            U64(0x30001060,0x30002000);U32(0x30001068,1);U32(0x3000106C,1);U64(0x30002000,0x30003000);
            U64(0x30003050,0x30005000);U64(0x300035CC,0x30004000);
            U32(0x30003398,0x100);Put(0x30003598,new byte[]{1});Put(0x300034FC,BitConverter.GetBytes(10f));
            SetCounts(0,64,64,0);U64(0x30006000,0x40000000);
            U32(0x30006094,0);U32(0x30006098,65);U32(0x3000609C,64);Put(0x300060A4,BitConverter.GetBytes(1f));
        }
        void Section(int index,uint start,uint size,uint flags){ulong at=Base+0x188+(ulong)index*40;U32(at+8,size);U32(at+12,start);U32(at+36,flags);}
        public void Put(ulong p,byte[] b){for(int i=0;i<b.Length;++i)bytes[p+(ulong)i]=b[i];}
        public void U16(ulong p,ushort n){Put(p,BitConverter.GetBytes(n));}
        public void U32(ulong p,uint n){Put(p,BitConverter.GetBytes(n));}
        public void U64(ulong p,ulong n){Put(p,BitConverter.GetBytes(n));}
        public void SetCounts(int spectators,int maximum,int humans,int bots){
            Put(0x300042E0,BitConverter.GetBytes(spectators));Put(0x300042E4,BitConverter.GetBytes(maximum));
            Put(0x300042EC,BitConverter.GetBytes(humans));Put(0x300042F0,BitConverter.GetBytes(bots));
        }
        public bool Alive(){return AliveValue;}
        public Region Query(ulong p){
            if(p>=Base && p<Base+Size){uint protect=p<Base+0x1000?2U:p<Base+0x2000?0x20U:p<Base+0x3000?2U:4U;
                ulong start=p<Base+0x1000?Base:p<Base+0x2000?Base+0x1000:p<Base+0x3000?Base+0x2000:Base+0x1700000;
                ulong length=p<Base+0x3000?0x1000UL:0x200000UL;
                return new Region{Base=start,Allocation=Base,Bytes=length,State=0x1000,Protect=protect,Type=0x1000000};}
            if(p>=0x30000000 && p<0x30007000)return new Region{Base=0x30000000,Allocation=0x30000000,Bytes=0x7000,State=0x1000,Protect=Guarded?0x104U:4U,Type=0x20000};
            return null;
        }
        public bool Read(ulong p,byte[] b){
            if(ShortRead)return false;
            if(p==0x30004000 && PendingKill)U64(p+12,1UL<<61);
            if(p==0x30003050 && WrongClass)U64(p,0);
            if(p==0x300042E0){++GameReads;if(GameReads==1 && ChangeHeaders)U32(Base+0xD0,123);if(GameReads==2 && ChangeCounts)SetCounts(0,64,63,0);}
            if(p==0x30006094 && ++OuterReads==2 && ChangeTimer)Put(0x300060A4,BitConverter.GetBytes(2f));
            for(int i=0;i<b.Length;++i){byte value;if(!bytes.TryGetValue(p+(ulong)i,out value))return false;b[i]=value;}return true;
        }
    }
    public static class Checks {
        static int count;
        static void Check(bool value,string message){++count;if(!value)throw new Exception(message);}
        static Observation Read(FakeMemory f){return new Reader(f,FakeMemory.Base,FakeMemory.Size).Capture();}
        static bool Has(Counts c,string name){return Array.IndexOf(c.FailedCountChecks,name)>=0;}
        public static int Run(){
            count=0;var f=new FakeMemory();var o=Read(f);
            Check(o.Stable && o.State=="count-and-identity-reads-agree","healthy observation: "+o.Detail);
            Check(o.Second.Humans==64 && o.Second.OuterCount==65 && o.Second.FailedCountChecks.Length==0,"PI 65 is not 65 humans or an invalid cap");
            for(int drift=1;drift<=3;++drift){
                f=new FakeMemory();f.SetCounts(-drift,64,62+drift,0);f.U32(0x30006098,63);o=Read(f);
                Check(o.Stable && o.Second.Spectators==-drift && o.Second.Humans==62+drift &&
                    o.Second.OuterCount==63 && o.Second.FailedCountChecks.Length==0,"raw drift retained without count projection");
            }
            f=new FakeMemory();f.SetCounts(0,64,64,1);o=Read(f);
            Check(o.Stable && o.Second.Humans==64 && o.Second.Bots==1 && o.Second.FailedCountChecks.Length==0,"obsolete aggregate cap removed");
            f=new FakeMemory();f.SetCounts(0,64,0,64);o=Read(f);
            Check(o.Stable && o.Second.Bots==64 && o.Second.FailedCountChecks.Length==0,"bots at capacity admitted");
            f=new FakeMemory();f.SetCounts(0,64,0,65);o=Read(f);
            Check(o.Stable && Has(o.Second,"game-bots-over-maximum"),"bots above capacity rejected");
            f=new FakeMemory();f.SetCounts(Int32.MinValue,64,Int32.MaxValue,0);o=Read(f);
            Check(o.Stable && o.Second.Spectators==Int32.MinValue && o.Second.Humans==Int32.MaxValue &&
                o.Second.FailedCountChecks.Length==0,"signed extremes retained without arithmetic");
            f=new FakeMemory();f.SetCounts(0,64,0,0);o=Read(f);Check(o.Stable && o.Second.Humans==0,"real zero distinguishable from unavailable");
            f=new FakeMemory();f.ChangeCounts=true;o=Read(f);Check(!o.Stable && o.State=="changed-during-read" && o.First.Humans==64 && o.Second.Humans==63,"changing snapshot retained, not qualified");
            f=new FakeMemory();f.ShortRead=true;o=Read(f);Check(!o.Stable && o.First==null && o.State=="unavailable","short read not a zero count");
            f=new FakeMemory();f.Guarded=true;o=Read(f);Check(!o.Stable && o.Detail=="memory-range-not-admitted","guarded memory rejected before access");
            f=new FakeMemory();f.PendingKill=true;o=Read(f);Check(!o.Stable && o.Detail=="object-pending-kill","dying object");
            f=new FakeMemory();f.WrongClass=true;o=Read(f);Check(!o.Stable,"wrong class rejected");
            f=new FakeMemory();f.AliveValue=false;o=Read(f);Check(!o.Stable && o.ReadCalls==0,"exited process no reads");
            f=new FakeMemory();f.U32(FakeMemory.Base+0xD0,123);o=Read(f);Check(!o.Stable && o.Detail=="host-header-mismatch","changed image headers");
            f=new FakeMemory();f.U64(0x30000080,0xFFFFFFFFFFFFFFF8);o=Read(f);Check(!o.Stable,"invalid pointer not dereferenced");
            f=new FakeMemory();f.U32(0x30006098,5000);o=Read(f);Check(o.Stable && Has(o.Second,"outer-count-outside-0-4096"),"outer count predicate");
            f=new FakeMemory();f.U32(0x3000609C,63);o=Read(f);Check(o.Stable && Array.IndexOf(o.Second.ReadinessNotes,"capacity-mismatch")>=0,"capacity mismatch separate from reason27");
            f=new FakeMemory();f.SetCounts(1,64,63,0);o=Read(f);Check(o.Stable && o.Second.FailedCountChecks.Length==0 && Array.IndexOf(o.Second.ReadinessNotes,"spectators-present")>=0,"positive spectators separate");
            f=new FakeMemory();f.PendingKill=true;o=Read(f);Check(o.Pass==1 && o.Stage=="game","failed stage preserved");
            f=new FakeMemory();f.ChangeHeaders=true;o=Read(f);Check(!o.Stable && o.Pass==2 && o.Stage=="headers" && o.First!=null,"headers rechecked across passes");
            f=new FakeMemory();f.ChangeTimer=true;o=Read(f);Check(!o.Stable && o.First.ProducerTimer==1 && o.Second.ProducerTimer==2,"producer transition retained");
            f=new FakeMemory();f.Put(0x300034FC,BitConverter.GetBytes(Single.NaN));o=Read(f);Check(o.Stable && Array.IndexOf(o.Second.ReadinessNotes,"world-not-ready")>=0,"unchanged invalid clock is readiness, not count change");
            return count;
        }
        public static int OwnProcessRead() {
            // Check the real Win32 ABI against a small allocation owned by this
            // test process. Never open VNGame or execute game/SDK code.
            int initial=count;IntPtr block=Marshal.AllocHGlobal(64);
            try {
                byte[] expected=new byte[64];for(int i=0;i<expected.Length;++i)expected[i]=(byte)(i+1);
                Marshal.Copy(expected,0,block,expected.Length);
                Process self=Process.GetCurrentProcess();ulong created=(ulong)self.StartTime.ToUniversalTime().ToFileTimeUtc();
                using(var m=new ProcessMemory((uint)self.Id,created)) {
                    var r=m.Query((ulong)block.ToInt64());Check(r!=null && r.State==0x1000 && r.Type==0x20000 && r.Protect==4,"real VirtualQueryEx ABI");
                    byte[] actual=new byte[64];Check(m.Read((ulong)block.ToInt64(),actual),"real read-only RPM");
                    bool same=true;for(int i=0;i<actual.Length;++i)same &= actual[i]==expected[i];
                    Check(same,"own memory unchanged/readback");
                }
                bool rejected=false;try {using(var m=new ProcessMemory((uint)self.Id,created+1)) {}}catch(InvalidOperationException){rejected=true;}
                Check(rejected,"creation identity mismatch refused");self.Dispose();
            }finally{Marshal.FreeHGlobal(block);}
            return count-initial;
        }
    }
}
