// Out-of-process, read-only scalar probe for the qualified full-dump PR3 build.
// These are nearby observations, NOT the tuple seen by a past DLL invocation.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace RS2CountProbe {
    public sealed class Region {
        public ulong Base, Allocation, Bytes;
        public uint State, Protect, Type;
    }
    public interface IMemory {
        bool Read(ulong address, byte[] bytes);
        Region Query(ulong address);
        bool Alive();
    }
    public sealed class ProcessMemory : IMemory, IDisposable {
        [StructLayout(LayoutKind.Sequential)] struct Mbi {
            public IntPtr Base, Allocation;
            public uint AllocationProtect;
            public ushort PartitionId, Padding;
            public UIntPtr Bytes;
            public uint State, Protect, Type, Padding2;
        }
        [StructLayout(LayoutKind.Sequential)] struct Ft { public uint Low, High; }
        [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool ReadProcessMemory(IntPtr handle, IntPtr address, byte[] bytes, UIntPtr size, out UIntPtr read);
        [DllImport("kernel32.dll", SetLastError=true)] static extern UIntPtr VirtualQueryEx(IntPtr handle, IntPtr address, out Mbi info, UIntPtr size);
        [DllImport("kernel32.dll")] static extern bool GetProcessTimes(IntPtr handle, out Ft creation, out Ft exit, out Ft kernel, out Ft user);
        [DllImport("kernel32.dll")] static extern bool GetExitCodeProcess(IntPtr handle, out uint code);
        IntPtr handle;
        public ProcessMemory(uint pid, ulong creation) {
            if (IntPtr.Size != 8) throw new InvalidOperationException("64-bit PowerShell is required.");
            // Query information + VM_READ only: no write, operation, suspend or thread rights.
            handle = OpenProcess(0x410, false, pid);
            if (handle == IntPtr.Zero) throw new InvalidOperationException("Read-only process open failed; Win32=" + Marshal.GetLastWin32Error());
            Ft c, e, k, u;
            if (!GetProcessTimes(handle, out c, out e, out k, out u) ||
                (((ulong)c.High << 32) | c.Low) != creation || !Alive()) {
                Dispose(); throw new InvalidOperationException("Process identity changed or process exited.");
            }
        }
        public bool Alive() { uint code; return handle != IntPtr.Zero && GetExitCodeProcess(handle, out code) && code == 259; }
        public bool Read(ulong address, byte[] bytes) {
            UIntPtr actual;
            return handle != IntPtr.Zero && ReadProcessMemory(handle, new IntPtr(checked((long)address)), bytes,
                new UIntPtr((uint)bytes.Length), out actual) && actual.ToUInt64() == (ulong)bytes.Length;
        }
        public Region Query(ulong address) {
            Mbi r;
            if (handle == IntPtr.Zero || VirtualQueryEx(handle, new IntPtr(checked((long)address)), out r,
                new UIntPtr((uint)Marshal.SizeOf(typeof(Mbi)))).ToUInt64() != (ulong)Marshal.SizeOf(typeof(Mbi))) return null;
            return new Region { Base=(ulong)r.Base.ToInt64(), Allocation=(ulong)r.Allocation.ToInt64(),
                Bytes=r.Bytes.ToUInt64(), State=r.State, Protect=r.Protect, Type=r.Type };
        }
        public void Dispose() { if (handle != IntPtr.Zero) { CloseHandle(handle); handle=IntPtr.Zero; } }
    }
    public sealed class Counts {
        public int Spectators, Humans, Bots, Maximum;
        public int OuterCount, OuterBots, OuterMaximum;
        public byte Requested, Dirty, NetMode;
        public bool BegunPlay;
        public int PendingTravelCharacters;
        public float WorldSeconds, ProducerTimer;
        public string[] FailedCountChecks;
        public string[] ReadinessNotes;
        // Pointers are internal comparison tokens and never serialized into evidence.
        internal ulong[] Identity;
    }
    public sealed class Observation {
        public string State="unavailable", Detail;
        public string Stage="not-started";
        public int Pass;
        public long BeginQpc, EndQpc;
        public Counts First, Second;
        public bool Stable;
        public int ReadCalls, QueryCalls;
    }
    public sealed class Reader {
        const uint WorldRva=0x17950C8, WorldClassRva=0x1783E80, PublicRva=0x17981A0, PrivateRva=0x17986E0;
        readonly IMemory memory;
        readonly ulong imageBase;
        readonly uint imageSize;
        readonly List<Section> sections=new List<Section>();
        int reads, queries;
        string stage;
        int pass;
        sealed class Section { public uint Start, Size, Flags; }
        public Reader(IMemory memory, ulong imageBase, uint imageSize) {
            this.memory=memory; this.imageBase=imageBase; this.imageSize=imageSize;
        }
        static void Require(bool ok, string detail) { if (!ok) throw new InvalidOperationException(detail); }
        static ulong Add(ulong a, ulong b) {
            Require(a >= 0x10000 && a <= 0x7FFFFFFFFFFF && b <= 0x7FFFFFFFFFFF-a, "address-range"); return a+b;
        }
        static bool Aligned(ulong p) { return p >= 0x10000 && p <= 0x7FFFFFFFFFFF && (p&7)==0; }
        void Range(ulong p, ulong size, uint type, uint protect) {
            ulong end=Add(p,size), at=p;
            Require(size != 0, "empty-range");
            for (int i=0; at<end && i<32; ++i) {
                ++queries; Region r=memory.Query(at);
                Require(r!=null && r.State==0x1000 && r.Type==type && r.Protect==protect &&
                    r.Allocation!=0 && r.Allocation<=r.Base && r.Base<=at && r.Bytes!=0 &&
                    r.Base<=0x7FFFFFFFFFFF && r.Bytes<=0x7FFFFFFFFFFF-r.Base && r.Base+r.Bytes>at,
                    "memory-range-not-admitted");
                if (type==0x1000000) Require(r.Allocation==imageBase, "image-allocation-changed");
                at=Math.Min(end,r.Base+r.Bytes);
            }
            Require(at==end,"region-limit");
        }
        byte[] Read(ulong p, int size, uint type, uint protect) {
            Require(size>0 && size<=4096,"read-size"); Range(p,(ulong)size,type,protect);
            byte[] b=new byte[size]; ++reads; Require(memory.Read(p,b),"read-failed-or-short"); return b;
        }
        byte[] Heap(ulong obj, uint offset, int size) { return Read(Add(obj,offset),size,0x20000,4); }
        static ulong U64(byte[] b,int n) { return BitConverter.ToUInt64(b,n); }
        static uint U32(byte[] b,int n) { return BitConverter.ToUInt32(b,n); }
        static int I32(byte[] b,int n) { return BitConverter.ToInt32(b,n); }
        ulong Pointer(ulong obj,uint offset) { return U64(Heap(obj,offset,8),0); }
        bool InSection(uint rva,uint size,uint required,uint forbidden) {
            int matches=0;
            foreach (Section s in sections) if (rva>=s.Start && rva-s.Start<s.Size && size<=s.Size-(rva-s.Start)) {
                if ((s.Flags&required)!=required || (s.Flags&forbidden)!=0) return false; ++matches;
            }
            return matches==1;
        }
        byte[] Image(uint rva,int size,uint flags,uint forbidden,uint protect) {
            Require(rva<imageSize && size>0 && (uint)size<=imageSize-rva && InSection(rva,(uint)size,flags,forbidden),"image-section");
            return Read(Add(imageBase,rva),size,0x1000000,protect);
        }
        void Headers() {
            sections.Clear(); Require(Aligned(imageBase) && imageSize>PrivateRva+8 && imageSize<=0x40000000,"host-image-size");
            byte[] dos=Read(imageBase,64,0x1000000,2); Require(BitConverter.ToUInt16(dos,0)==0x5A4D,"dos-header");
            uint nt=U32(dos,60); Require(nt>=64 && nt<=0x100000 && nt<imageSize-264,"nt-offset");
            byte[] h=Read(Add(imageBase,nt),264,0x1000000,2);
            ushort count=BitConverter.ToUInt16(h,6), optional=BitConverter.ToUInt16(h,20);
            Require(U32(h,0)==0x4550 && BitConverter.ToUInt16(h,4)==0x8664 &&
                BitConverter.ToUInt16(h,24)==0x20B && U32(h,80)==imageSize &&
                count>0 && count<=96 && optional>=240 && optional<=4096,"host-header-mismatch");
            ulong table=(ulong)nt+24+optional; Require(table+(uint)count*40<=imageSize,"section-table-range");
            byte[] entries=Read(Add(imageBase,table),count*40,0x1000000,2); ulong last=0;
            for (int i=0;i<count;++i) {
                uint start=U32(entries,i*40+12), length=U32(entries,i*40+8);
                Require(start>=last && start<=imageSize && length<=imageSize-start,"section-overlap-or-size");
                sections.Add(new Section{Start=start,Size=length,Flags=U32(entries,i*40+36)}); last=(ulong)start+length;
            }
        }
        ulong Global(uint rva) { return U64(Image(rva,8,0xC0000000,0x22000000,4),0); }
        void Object(ulong p,bool actor,List<ulong> identity) {
            Require(Aligned(p),"object-alignment"); byte[] fields=Heap(p,0,20);
            ulong table=U64(fields,0); Require((U64(fields,12)&(1UL<<61))==0,"object-pending-kill");
            Require(Aligned(table) && table>=imageBase && table-imageBase<imageSize,"vtable-range");
            ulong target=U64(Image((uint)(table-imageBase),8,0x40000000,0xA2000000,2),0);
            Require(target>=imageBase && target-imageBase<imageSize,"virtual-target-range");
            uint trva=(uint)(target-imageBase);
            Require(InSection(trva,1,0x60000000,0x82000000),"virtual-target-section"); Range(target,1,0x1000000,0x20);
            if (actor) Require((Heap(p,0x60,1)[0]&0x20)==0,"actor-pending-delete");
            identity.Add(p); identity.Add(table);
        }
        Counts Once() {
            List<ulong> identity=new List<ulong>(); Counts c=new Counts();
            stage="world-root";ulong world=Global(WorldRva);
            stage="world";Object(world,false,identity);
            stage="level";
            ulong level=Pointer(world,0x80); Object(level,false,identity);
            stage="actors";
            byte[] array=Heap(level,0x60,16); ulong actors=U64(array,0); int count=I32(array,8),capacity=I32(array,12);
            Require(Aligned(actors) && count>0 && capacity>=count && capacity<=1048576,"actor-array");
            Range(actors,(ulong)capacity*8,0x20000,4); identity.Add(actors);
            stage="worldinfo";ulong info=U64(Heap(actors,0,8),0); Object(info,true,identity);
            stage="world-class-root";ulong expected=Global(WorldClassRva);
            Require(expected!=0,"world-class-uninitialized"); identity.Add(expected);
            stage="world-class-chain";
            ulong current=Pointer(info,0x50); HashSet<ulong> seen=new HashSet<ulong>(); bool match=false;
            for(int depth=0;depth<64;++depth) {
                Require(seen.Add(current),"class-cycle"); Object(current,false,identity);
                if(current==expected){match=true;break;} current=Pointer(current,0x78);
            }
            Require(match,"world-class-mismatch");
            stage="game";ulong game=Pointer(info,0x5CC); Object(game,true,identity);
            stage="world-readiness";
            c.BegunPlay=(U32(Heap(info,0x398,4),0)&0x100)!=0;
            c.NetMode=Heap(info,0x598,1)[0]; c.WorldSeconds=BitConverter.ToSingle(Heap(info,0x4FC,4),0);
            stage="travel";byte[] travel=Heap(info,0x624,16); ulong data=U64(travel,0); int chars=I32(travel,8),cap=I32(travel,12);
            Require(chars>=0 && cap>=chars && cap<=65536,"travel-array");
            if(cap==0) Require(data==0 && chars==0,"travel-empty-array");
            else { Require(data>=0x10000 && (data&1)==0,"travel-alignment"); Range(data,(ulong)cap*2,0x20000,4); }
            c.PendingTravelCharacters=chars; identity.Add(data);
            // Preserve signed values BEFORE applying the reporting policy. Never
            // turn a rejected/negative tuple into a zero-occupancy observation.
            stage="counts";byte[] raw=Heap(game,0x2E0,20);
            c.Spectators=I32(raw,0); c.Maximum=I32(raw,4); c.Humans=I32(raw,12); c.Bots=I32(raw,16);
            stage="wrapper-roots";ulong wrapper=Global(PublicRva),other=Global(PrivateRva);
            Require(Aligned(wrapper) && wrapper==other,"wrapper-roots-mismatch"); identity.Add(wrapper);
            stage="wrapper-interface";ulong api=Pointer(wrapper,0); Require(Aligned(api),"interface-pointer"); identity.Add(api);
            // No interface method, Steam API, game function or actor list is invoked.
            stage="outer-counts";byte[] outer=Heap(wrapper,0x94,20);
            c.OuterBots=I32(outer,0); c.OuterCount=I32(outer,4); c.OuterMaximum=I32(outer,8);
            c.Requested=outer[12]; c.Dirty=outer[13]; c.ProducerTimer=BitConverter.ToSingle(outer,16);
            c.Identity=identity.ToArray(); c.FailedCountChecks=CountChecks(c); c.ReadinessNotes=Readiness(c);
            return c;
        }
        public static string[] CountChecks(Counts c) {
            List<string> f=new List<string>();
            if(c.Maximum<0 || c.Maximum>255) f.Add("maximum-outside-0-255");
            if(c.Humans<0) f.Add("negative-humans"); if(c.Bots<0) f.Add("negative-bots");
            // Reporting 0.4.2.0 admits raw H/S drift; only bots feed the staged
            // native count input. Preserve the signed observations without clamping.
            if(c.Bots>=0 && c.Maximum>=0 && c.Bots>c.Maximum) f.Add("game-bots-over-maximum");
            if(c.OuterBots<0 || c.OuterBots>255) f.Add("outer-bots-outside-0-255");
            if(c.OuterCount<0 || c.OuterCount>4096) f.Add("outer-count-outside-0-4096");
            return f.ToArray();
        }
        static bool Finite(float f) { return !Single.IsNaN(f) && !Single.IsInfinity(f) && f>=0; }
        static string[] Readiness(Counts c) {
            List<string> f=new List<string>();
            if(!c.BegunPlay || c.NetMode!=1 || !Finite(c.WorldSeconds)) f.Add("world-not-ready");
            if(c.PendingTravelCharacters!=0) f.Add("pending-travel");
            if(c.Spectators>0) f.Add("spectators-present");
            if(c.OuterMaximum!=c.Maximum) f.Add("capacity-mismatch");
            if(c.Requested>1 || c.Dirty>1 || !Finite(c.ProducerTimer)) f.Add("producer-fields-invalid");
            return f.ToArray();
        }
        static bool Same(Counts a,Counts b) {
            if(a.Identity.Length!=b.Identity.Length)return false;
            for(int i=0;i<a.Identity.Length;++i)if(a.Identity[i]!=b.Identity[i])return false;
            if(a.ReadinessNotes.Length!=b.ReadinessNotes.Length)return false;
            for(int i=0;i<a.ReadinessNotes.Length;++i)if(a.ReadinessNotes[i]!=b.ReadinessNotes[i])return false;
            return a.Spectators==b.Spectators && a.Humans==b.Humans && a.Bots==b.Bots && a.Maximum==b.Maximum &&
                a.OuterCount==b.OuterCount && a.OuterBots==b.OuterBots && a.OuterMaximum==b.OuterMaximum &&
                a.Requested==b.Requested && a.Dirty==b.Dirty && a.BegunPlay==b.BegunPlay && a.NetMode==b.NetMode &&
                a.PendingTravelCharacters==b.PendingTravelCharacters && a.ProducerTimer.Equals(b.ProducerTimer) &&
                (Finite(a.WorldSeconds) && Finite(b.WorldSeconds) ? b.WorldSeconds>=a.WorldSeconds : a.WorldSeconds.Equals(b.WorldSeconds));
        }
        public Observation Capture() {
            Observation o=new Observation(); reads=0;queries=0;pass=0;stage="process-before";o.BeginQpc=Stopwatch.GetTimestamp();
            try {
                Require(memory.Alive(),"process-exited");
                pass=1;stage="headers";Headers();o.First=Once();
                pass=2;stage="headers";Headers();o.Second=Once();
                stage="process-after";Require(memory.Alive(),"process-exited");
                stage="comparison";o.Stable=Same(o.First,o.Second);
                o.State=o.Stable?"count-and-identity-reads-agree":"changed-during-read";
                if(o.Stable)stage="complete";
                o.Detail="External observations only; not atomic, not a DLL-event tuple, not full source admission.";
            } catch(InvalidOperationException e) {o.Detail=e.Message;} catch(OverflowException){o.Detail="address-overflow";}
            finally {o.EndQpc=Stopwatch.GetTimestamp();o.ReadCalls=reads;o.QueryCalls=queries;o.Stage=stage;o.Pass=pass;}
            return o;
        }
    }
}
