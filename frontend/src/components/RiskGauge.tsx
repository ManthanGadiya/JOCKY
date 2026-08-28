export default function RiskGauge({risk}:{risk:number}){
  const pct = Math.min(risk,100)
  const color = pct>80?'#dc2626':pct>60?'#f59e0b':'#22c55e'
  return <div className="bg-zinc-900 rounded-xl p-4 border border-zinc-800">
    <h3 className="font-semibold">Risk Score 0-100 (Behavioral)</h3>
    <div className="mt-3 h-4 bg-zinc-800 rounded-full overflow-hidden"><div className="h-full" style={{width: pct+'%', background: color}} /></div>
    <div className="text-3xl font-bold mt-2" style={{color}}>{pct}/100 <span className="text-sm font-normal text-zinc-400">{pct>80?'CRITICAL':pct>60?'HIGH':'MEDIUM'}</span></div>
    <div className="text-xs text-zinc-500 mt-1">Weighted: PPID*30 + hollowed*40 + driver_vuln*30 (no hash reliance)</div>
  </div>
}
