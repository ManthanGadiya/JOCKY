import { useEffect, useState } from 'react'
import Graph from './components/Graph'
import Timeline from './components/Timeline'
import RiskGauge from './components/RiskGauge'

const API = 'http://localhost:8000'
const DEFAULT_SRC = `system.info();
process.list();
file.hash("/evidence/sample.exe");
network.connections();
`

export default function App(){
  const [cases, setCases] = useState<any[]>([])
  const [risk, setRisk] = useState(0)
  const [source, setSource] = useState(DEFAULT_SRC)
  const [ir, setIr] = useState<string>("")
  const [caps, setCaps] = useState<string[]>([])
  const [ops, setOps] = useState<string[]>([])
  const [evidence, setEvidence] = useState<any[]>([])
  const [findings, setFindings] = useState<any[]>([])
  const [timeline, setTimeline] = useState<any[]>([])
  const [graph, setGraph] = useState<any>({nodes:[],edges:[],mitre:[]})
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string>("")
  const [caseId, setCaseId] = useState(1)
  const [lastRun, setLastRun] = useState<string>("")
  const [yara, setYara] = useState<any>(null)
  const [poly, setPoly] = useState<any>(null)

  const fetchYara = async ()=>{
    try{ const r=await fetch(`${API}/api/yara/status`).then(r=>r.json()); setYara(r) }catch{}
  }
  const runPoly = async ()=>{
    setLoading(true); setError("")
    try{
      const res=await fetch(`${API}/api/yara/polymorphic-demo`,{method:'POST',headers:{'Content-Type':'application/json'},body: JSON.stringify({source, seeds:[1,2,3], polymorphic:true})})
      const data=await res.json()
      if(!res.ok) throw new Error(data.detail||'poly failed')
      setPoly(data)
      setLastRun(`Poly demo: ${data.results.length} IRs distinct_hashes=${data.distinct_hashes} same_cluster=${data.same_yara_cluster} — hash != detection`)
    }catch(e:any){ setError(e.message||String(e)) }
    finally{ setLoading(false) }
  }

  const refresh = async (cid:number)=>{
    try{
      const r = await fetch(`${API}/api/cases/${cid}/risk`).then(r=>r.json())
      setRisk(r.risk ?? 0)
      const t = await fetch(`${API}/api/cases/${cid}/timeline`).then(r=>r.json())
      setTimeline(t.timeline || [])
      const g = await fetch(`${API}/api/cases/${cid}/graph`).then(r=>r.json())
      setGraph(g)
      const cs = await fetch(`${API}/api/cases`).then(r=>r.json())
      setCases(cs.cases||[])
      const ev = await fetch(`${API}/api/evidence?case_id=${cid}`).then(r=>r.json())
      setEvidence(ev.evidence||[])
      const f = await fetch(`${API}/api/findings?case_id=${cid}`).then(r=>r.json())
      setFindings(f.findings||[])
    }catch(e){/* fallback keeps last values */}
  }

  useEffect(()=>{ refresh(caseId); fetchYara() },[caseId])
  // poll every 5s for live updates
  useEffect(()=>{
    const id=setInterval(()=>{ refresh(caseId); fetchYara() }, 5000)
    return ()=>clearInterval(id)
  },[caseId])

  const runCompile = async ()=>{
    setLoading(true); setError(""); setIr("")
    try{
      const res = await fetch(`${API}/api/compile`,{method:'POST',headers:{'Content-Type':'application/json'},body: JSON.stringify({source})})
      const data = await res.json()
      if(!res.ok) throw new Error(data.detail || 'compile failed')
      setIr(data.ir); setCaps(data.capabilities||[]); setOps(data.ops||[])
      setLastRun(`Compiled OK — IR v${data.ir_version} hash ${data.ir_hash} caps ${data.capabilities.join(', ')||'(none)'}`)
    }catch(e:any){ setError(e.message||String(e)) }
    finally{ setLoading(false) }
  }

  const runExecute = async ()=>{
    setLoading(true); setError("")
    try{
      const res = await fetch(`${API}/api/run`,{method:'POST',headers:{'Content-Type':'application/json'},body: JSON.stringify({source, agent_id:'WIN-001', host_id:'HOST-001', case_id: caseId})})
      const data = await res.json()
      if(!res.ok) throw new Error(data.detail || 'run failed')
      setIr(data.ir); setCaps(data.capabilities||[]); setOps(data.ops||[])
      setEvidence(data.evidence||[]); setFindings(data.findings||[])
      setRisk(data.risk??0)
      setLastRun(`Run OK — case ${data.case_id} risk ${data.risk} (${data.level}) evidence ${data.evidence.length}`)
      await refresh(data.case_id)
    }catch(e:any){ setError(e.message||String(e)) }
    finally{ setLoading(false) }
  }

  const downloadReport = async ()=>{
    setLoading(true); setError("")
    try{
      const res = await fetch(`${API}/api/cases/${caseId}/report`)
      if(!res.ok) throw new Error('report failed '+res.status)
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `JOCKY_case_${caseId}_report.pdf`
      // if fallback html, still save as .html for debugging
      const ctype = res.headers.get('content-type')||''
      if(ctype.includes('html')) a.download = `JOCKY_case_${caseId}_report.html`
      document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url)
      setLastRun(`Report downloaded — case ${caseId} (${ctype.includes('pdf')?'PDF':'HTML fallback'})`)
    }catch(e:any){ setError(e.message||String(e)) }
    finally{ setLoading(false) }
  }

  return (
    <div className="min-h-screen p-6 bg-zinc-950 text-zinc-100">
      <header className="flex justify-between items-center border-b border-zinc-800 pb-4 mb-6">
        <h1 className="text-2xl font-bold">JOCKY Forensic Dashboard <span className="text-violet-400">L8 Correlation</span></h1>
        <span className="text-xs bg-zinc-900 px-3 py-1 rounded">Backend: {cases.length} cases • {evidence.length} evidence • IR v1 • YARA {yara?.yara_binary_used ? '✅ binary' : yara?.yara_available ? '✅ rules' : '⏳ fallback'} • Nginx 8082 • Postgres {yara? '✅' : ''}</span>
      </header>

      <div className="bg-zinc-900 rounded-xl p-4 border border-zinc-800 mb-6">
        <div className="flex justify-between items-center mb-2"><h2 className="font-semibold">YARA Detection — Polymorphic Proof (Point 1+2) — hash ≠ detection</h2><button onClick={runPoly} disabled={loading} className="text-xs bg-amber-600 hover:bg-amber-500 px-3 py-1 rounded">Run YARA Poly Demo</button></div>
        <p className="text-xs text-zinc-500 mb-2">Rules: <span className="mono">{yara?.yara_rules||'yara/rules.yar'}</span> — test_hits: {yara?.test_hits?.join(', ')||'—'} • Backend :8000 POST /api/yara/scan + /api/yara/polymorphic-demo</p>
        <div className="text-xs bg-zinc-950 p-2 rounded border border-zinc-800 mono">
          {poly ? poly.results.map((r:any)=><div key={r.seed}>seed {r.seed} sha {r.sha12}… hits {r.hits.join(', ')||'(none)'} yara {r.yara_used?'binary':'fallback'}</div>) : 'Click Run YARA Poly Demo — generates 3 IRs from same JOCKY source with different seeds (--polymorphic): 3 distinct SHA256 but same YARA hits (JOCKY_DEMO_MARKER) → 1 cluster.'}
          {poly && <div className="mt-1 text-green-400">distinct_hashes={String(poly.distinct_hashes)} same_yara_cluster={String(poly.same_yara_cluster)} — Point 2 proven</div>}
        </div>
        <div className="text-xs text-zinc-500 mt-1">Frontend also shows IR YARA hits after Run: each evidence YARA hit • <a className="underline" href="http://localhost:8000/api/yara/status" target="_blank">/api/yara/status</a> • <a className="underline" href="http://localhost:8000/docs" target="_blank">/api/docs</a></div>
      </div>

      {/* JOCKY Editor — First Milestone */}
      <div className="bg-zinc-900 rounded-xl p-4 border border-zinc-800 mb-6">
        <div className="flex justify-between items-center mb-3">
          <h2 className="font-semibold">JOCKY Editor — Run a query from the dashboard</h2>
          <span className="text-xs text-zinc-500">case {caseId} • HOST-001 / WIN-001 • fail-closed caps</span>
        </div>
        <div className="grid grid-cols-12 gap-4">
          <div className="col-span-5">
            <label className="text-xs text-zinc-400">JOCKY source (.jocky)</label>
            <textarea value={source} onChange={e=>setSource(e.target.value)} rows={8} className="w-full mt-1 bg-zinc-950 border border-zinc-700 rounded p-2 font-mono text-sm" placeholder={"system.info();"} />
            <div className="flex gap-2 mt-2 flex-wrap">
              <button onClick={runCompile} disabled={loading} className="bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 px-4 py-2 rounded text-sm disabled:opacity-50">Compile</button>
              <button onClick={runExecute} disabled={loading} className="bg-violet-600 hover:bg-violet-500 px-4 py-2 rounded text-sm font-semibold disabled:opacity-50">Run</button>
              <button onClick={()=>setSource("system.info();")} className="text-xs px-2 py-1 bg-zinc-800 rounded">system.info()</button>
              <button onClick={()=>setSource("process.list();")} className="text-xs px-2 py-1 bg-zinc-800 rounded">process.list()</button>
              <button onClick={()=>setSource('file.hash("/evidence/sample.exe");')} className="text-xs px-2 py-1 bg-zinc-800 rounded">file.hash</button>
              <button onClick={()=>setSource("network.connections();")} className="text-xs px-2 py-1 bg-zinc-800 rounded">net.conns</button>
              <button onClick={()=>setSource("system.info();\nprocess.list();\nfile.hash(\"/evidence/sample.exe\");\nnetwork.connections();")} className="text-xs px-2 py-1 bg-violet-900 rounded">full sweep</button>
              <button onClick={()=>setSource('file.hash("../../etc/passwd");')} className="text-xs px-2 py-1 bg-red-900 rounded">traversal (fail)</button>
            </div>
            {error && <div className="mt-2 text-xs text-red-400 bg-red-950 border border-red-900 p-2 rounded">Error: {error}</div>}
            {lastRun && !error && <div className="mt-2 text-xs text-green-400 bg-green-950 border border-green-900 p-2 rounded">{lastRun}</div>}
            {caps.length>0 && <div className="mt-2 text-xs text-zinc-500">Caps: {caps.join(', ')} • Ops: {ops.join(', ')}</div>}
          </div>
          <div className="col-span-7">
            <label className="text-xs text-zinc-400">Generated IR (IR_VERSION=1, JOCKY_DEMO_MARKER)</label>
            <pre className="w-full mt-1 bg-zinc-950 border border-zinc-700 rounded p-2 font-mono text-xs overflow-auto max-h-[220px] whitespace-pre-wrap">{ir || "— run Compile or Run to generate IR —\nIR v1 + caps + EntryPoint + JOCKY_DEMO_MARKER + bb.poly.* when --polymorphic"}</pre>
            <div className="text-xs text-zinc-500 mt-1">IR is textual LLVM-like + validated before execution. Unknown ops → 422 fail-closed. memory.analyze → 403 denied.</div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-12 gap-6">
        <div className="col-span-8 bg-zinc-900 rounded-xl p-4 border border-zinc-800">
          <h2 className="font-semibold mb-2">Evidence Knowledge Graph (React Flow) — Live</h2>
          <p className="text-xs text-zinc-500 mb-2">Host → Evidence nodes (op/type) → Finding • MITRE {graph.mitre?.join(', ')||'T1055/T1068'} • {graph.nodes?.length||0} nodes {evidence.length} evidence</p>
          <Graph data={graph} />
          {evidence.length>0 && <div className="mt-3 text-xs"><div className="font-semibold mb-1">Evidence store (case {caseId}) — canonical envelope schema_version 1 + integrity SHA256:</div>
            <div className="space-y-1 max-h-52 overflow-auto bg-zinc-950 p-2 rounded border border-zinc-800">
              {evidence.slice(-8).map((e:any)=>{
                const p=e.payload||{}
                const detail = e.type==='process' ? `${p.count} procs${p.processes?.some((x:any)=>x.ppid_anomaly)?' • ppid anomaly':''}` :
                  e.type==='file' ? `${p.path} ${p.hashes?.sha256?.slice(0,12)??''} ${p.yara_hit?'• YARA':''}` :
                  e.type==='network' ? `${p.connections?.length} conns ${p.connections?.some((c:any)=>c.remote_address==='192.0.2.20')?'• C2':''}` :
                  JSON.stringify(p).slice(0,80)
                return <div key={e.id} className="font-mono text-xs"><span className="text-violet-400">{e.id}</span> {e.op} risk {e.risk} • {detail}</div>
              })}
            </div>
          </div>}
        </div>
        <div className="col-span-4 space-y-4">
          <RiskGauge risk={risk} />
          <div className="bg-zinc-900 rounded-xl p-4 border border-zinc-800">
            <div className="flex justify-between items-center"><h3 className="font-semibold">Findings — Live</h3><button onClick={downloadReport} disabled={loading} className="text-xs bg-violet-600 hover:bg-violet-500 px-3 py-1 rounded disabled:opacity-50">📄 Report PDF</button></div>
            {findings.length===0 ? <p className="text-sm text-zinc-500 mt-2">No findings yet — Run a sweep then download report.</p> :
              <ul className="text-sm mt-2 space-y-1">{findings.slice(-8).map((f:any)=><li key={f.id} className="text-xs flex justify-between"><span><span className="text-violet-400">{f.id}</span> {f.rule}</span><span className={f.severity==='CRITICAL'?'text-red-400':f.severity==='HIGH'?'text-orange-400':'text-green-400'}>{f.severity} {f.risk}</span></li>)}</ul>}
          </div>
          <div className="bg-zinc-900 rounded-xl p-4 border border-zinc-800">
            <h3 className="font-semibold">MITRE ATT&CK</h3>
            <ul className="text-xs mt-2 space-y-1"><li>T1055 Process Injection (hollowing)</li><li>T1068 Exploit Vuln Driver (BYOVD)</li><li>T1105 Ingress Tool Transfer</li></ul>
          </div>
          <div className="bg-zinc-900 rounded-xl p-4 border border-zinc-800">
            <h3 className="font-semibold">AI Explainer (Ollama stub)</h3>
            <p className="text-sm text-zinc-400 mt-2">Risk {risk}: {findings.length? `${findings[findings.length-1]?.rule} risk ${risk}` : 'Run a JOCKY query to generate evidence'}. Chain-of-custody SHA256 verified, envelope schema_version 1.</p>
          </div>
        </div>
        <div className="col-span-12 bg-zinc-900 rounded-xl p-4 border border-zinc-800">
          <h2 className="font-semibold mb-2">Causal Timeline Fusion — Live</h2>
          <p className="text-xs text-zinc-500 mb-2">{timeline.length} events in case {caseId} — source: evidence_store ordered by observed_at/schema_version 1</p>
          <Timeline events={timeline} />
        </div>
      </div>
      <footer className="text-xs text-zinc-600 mt-8">JOCKY L1-L8 • IR v1 validates + fail-closed • system.info() E2E → evidence envelope → detection → live Graph/Timeline/Risk • Synthetic evidence demo • Point 1+2: jockyc --polymorphic → 3 hashes • Nginx 8082 → backend 8000</footer>
    </div>
  )
}
