import { useState } from 'react'
export default function RiskGauge({risk, history}:{risk:number, history?:number[]}){
  const pct = Math.min(risk,100)
  const color = pct>80?'#dc2626':pct>60?'#f59e0b':'#22c55e'
  const hist = (history && history.length>1) ? history.slice(-20) : []
  const max = Math.max(...hist, 100)
  const [showDetail, setShowDetail] = useState(false)
  const [breakdown, setBreakdown] = useState<any>(null)
  const spark = hist.length>1 ? (()=> {
    const w=120,h=28,pad=2
    const pts = hist.map((v,i)=>{
      const x = pad + (i/(hist.length-1))*(w-pad*2)
      const y = h - pad - (v/max)*(h-pad*2)
      return `${x},${y}`
    }).join(' ')
    return <svg width={w} height={h} className="border border-zinc-800 rounded bg-zinc-950"><polyline fill="none" stroke={color} strokeWidth={1.8} points={pts} /></svg>
  })() : null
  const loadBreakdown = async ()=>{
    if(showDetail) { setShowDetail(false); return }
    try{
      const caseId = 1
      const r = await fetch(`http://localhost:8000/api/cases/${caseId}/risk/breakdown`).then(x=>x.json())
      setBreakdown(r); setShowDetail(true)
    }catch{ setShowDetail(true)}
  }
  return <div className="bg-zinc-900 rounded-xl p-4 border border-zinc-800">
    <h3 className="font-semibold flex justify-between items-center">Risk Score 0-100 (Behavioral) <button onClick={loadBreakdown} className="text-xs bg-zinc-800 px-2 py-1 rounded">{showDetail?'hide':'detail'}</button></h3>
    <div className="mt-3 h-4 bg-zinc-800 rounded-full overflow-hidden"><div className="h-full transition-all" style={{width: pct+'%', background: color}} /></div>
    <div className="text-3xl font-bold mt-2" style={{color}}>{pct}/100 <span className="text-sm font-normal text-zinc-400">{pct>80?'CRITICAL':pct>60?'HIGH':pct>30?'MEDIUM':'LOW'}</span></div>
    <div className="text-xs text-zinc-500 mt-1">Weighted: PPID*30 + hollowed*40 + driver*15 + yara*20 + C2*30 (hash≠detection)</div>
    {spark && <div className="mt-2"><div className="text-xs text-zinc-500">History (last {hist.length})</div>{spark}</div>}
    {showDetail && <div className="mt-2 text-xs bg-zinc-950 p-2 rounded border border-zinc-800 max-h-40 overflow-auto">
      <div className="font-semibold mb-1">Breakdown (per evidence)</div>
      {breakdown ? breakdown.breakdown.map((b:any)=><div key={b.id} className="mb-1"><span className="text-violet-400">{b.id}</span> {b.type} r={b.risk} {b.mitre? `· ${b.mitre}`:''} <span className="text-zinc-500">{b.behavioral?.slice(0,2).map((x:any)=> x.rule).join(', ')}</span></div>) : 'loading...'}
      <div className="mt-1 text-zinc-500"><a className="underline" href="http://localhost:8000/api/cases/1/risk/history" target="_blank">/risk/history</a> · <a className="underline" href="http://localhost:8000/api/cases/1/risk/breakdown" target="_blank">/risk/breakdown</a></div>
    </div>}
  </div>
}
