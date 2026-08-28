import { useEffect, useState } from 'react'
import Graph from './components/Graph'
import Timeline from './components/Timeline'
import RiskGauge from './components/RiskGauge'

export default function App(){
  const [cases, setCases] = useState<any[]>([])
  const [risk, setRisk] = useState(85)
  useEffect(()=>{
    fetch('http://localhost:8000/api/cases').then(r=>r.json()).then(d=>setCases(d.cases||[])).catch(()=>{})
    fetch('http://localhost:8000/api/cases/1/risk').then(r=>r.json()).then(d=>setRisk(d.risk||85)).catch(()=>{})
  },[])
  return (
    <div className="min-h-screen p-6">
      <header className="flex justify-between items-center border-b border-zinc-800 pb-4 mb-6">
        <h1 className="text-2xl font-bold">JOCKY Forensic Dashboard <span className="text-violet-400">L8 Correlation</span></h1>
        <span className="text-xs bg-zinc-900 px-3 py-1 rounded">Backend: {cases.length} cases • Nginx CDN proxy • WSS</span>
      </header>
      <div className="grid grid-cols-12 gap-6">
        <div className="col-span-8 bg-zinc-900 rounded-xl p-4 border border-zinc-800">
          <h2 className="font-semibold mb-2">Evidence Knowledge Graph (React Flow) - Risk Propagation</h2>
          <p className="text-xs text-zinc-500 mb-2">User → Process → File → Network → Driver → Finding • MITRE T1055 / T1068</p>
          <Graph />
        </div>
        <div className="col-span-4 space-y-4">
          <RiskGauge risk={risk} />
          <div className="bg-zinc-900 rounded-xl p-4 border border-zinc-800">
            <h3 className="font-semibold">AI Explainer (Ollama stub)</h3>
            <p className="text-sm text-zinc-400 mt-2">Risk {risk}: Hollowed explorer.exe (T1055.012) + RTCore64 vulnerable driver (T1068) + ESTABLISHED C2 to 185.220.101.5. Chain-of-custody SHA256 verified.</p>
          </div>
          <div className="bg-zinc-900 rounded-xl p-4 border border-zinc-800">
            <h3 className="font-semibold">MITRE ATT&CK</h3>
            <ul className="text-xs mt-2 space-y-1"><li>T1055 Process Injection (hollowing)</li><li>T1068 Exploit Vuln Driver (BYOVD)</li><li>T1105 Ingress Tool Transfer</li></ul>
          </div>
        </div>
        <div className="col-span-12 bg-zinc-900 rounded-xl p-4 border border-zinc-800">
          <h2 className="font-semibold mb-2">Causal Timeline Fusion (6 sources)</h2>
          <Timeline />
        </div>
      </div>
      <footer className="text-xs text-zinc-600 mt-8">JOCKY L1-L8 • Docker-only • Synthetic evidence demo • Point 1+2: jockyc --polymorphic → 3 hashes • 3A+3B: detection on testdata/*.json • Central via Nginx</footer>
    </div>
  )
}
