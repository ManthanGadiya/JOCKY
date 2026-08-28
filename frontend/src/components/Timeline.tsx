const events = [
  { t:"10:30:00", src:"log", msg:"User analyst login (WIN-001)", risk:0 },
  { t:"10:31:12", src:"file", msg:"File drop C:\\Temp\\suspicious.exe (SHA256 a1b2...)", risk:20 },
  { t:"10:32:03", src:"memory", msg:"Process hollowing: explorer.exe (1234) MEM_PRIVATE RX unbacked", risk:65 },
  { t:"10:32:45", src:"network", msg:"C2 ESTABLISHED 185.220.101.5:443", risk:80 },
  { t:"10:33:10", src:"driver", msg:"Vulnerable driver RTCore64.sys loaded (BYOVD T1068)", risk:85 },
]
export default function Timeline(){
  return <div className="flex gap-2 overflow-x-auto py-2">{events.map(e=><div key={e.t} className="min-w-[180px] bg-zinc-800 rounded-lg p-3 border border-zinc-700"><div className="text-xs text-violet-400">{e.t} • {e.src}</div><div className="text-sm mt-1">{e.msg}</div><div className="text-xs mt-1 text-red-400">Risk {e.risk}</div></div>)}</div>
}
