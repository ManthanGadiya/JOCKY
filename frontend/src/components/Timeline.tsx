type Evt = { id?:string, timestamp?:string|number, type?:string, op?:string, payload?:any, risk?:number, host_id?:string, agent_id?:string }
export default function Timeline({events}:{events?:Evt[]}){
  if(!events || events.length===0){
    const fallback = [
      { t:"10:30:00", src:"log", msg:"User analyst login (WIN-001)", risk:0 },
      { t:"10:31:12", src:"file", msg:"File drop C:\\Temp\\suspicious.exe (SHA256 a1b2...)", risk:20 },
      { t:"10:32:03", src:"memory", msg:"Process hollowing: explorer.exe (1234) MEM_PRIVATE RX unbacked", risk:65 },
      { t:"10:32:45", src:"network", msg:"C2 ESTABLISHED 185.220.101.5:443", risk:80 },
      { t:"10:33:10", src:"driver", msg:"Vulnerable driver RTCore64.sys loaded (BYOVD T1068)", risk:85 },
    ]
    return (<div><div className="text-xs text-zinc-500 mb-2">Demo fallback — no live evidence yet. Run system.info(); to populate.</div>
      <div className="flex gap-2 overflow-x-auto py-2">{fallback.map(e=><div key={e.t} className="min-w-[180px] bg-zinc-800 rounded-lg p-3 border border-zinc-700"><div className="text-xs text-violet-400">{e.t} • {e.src}</div><div className="text-sm mt-1">{e.msg}</div><div className="text-xs mt-1 text-red-400">Risk {e.risk}</div></div>)}</div></div>)
  }
  return <div className="flex gap-2 overflow-x-auto py-2">{events.map((e,i)=><div key={e.id||i} className="min-w-[220px] bg-zinc-800 rounded-lg p-3 border border-zinc-700">
    <div className="text-xs text-violet-400">{String(e.timestamp||'').slice(0,19)} • {e.op||e.type}</div>
    <div className="text-sm mt-1">{e.id} — {e.type} {e.op}</div>
    <div className="text-xs mt-1 text-zinc-400">{e.host_id||e.agent_id}</div>
    <div className="text-xs mt-1 text-red-400">Risk {e.risk??0}</div>
  </div>)}</div>
}
