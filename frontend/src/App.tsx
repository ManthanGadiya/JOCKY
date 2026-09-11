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
  // Case isolation + host/filter per ARCHITECTURE §11 + FORENSICS §7 (evidence must belong to case) + ROADMAP §11
  const [hostFilter, setHostFilter] = useState<string>("all")
  const [typeFilter, setTypeFilter] = useState<string>("all")
  const [platformFilter, setPlatformFilter] = useState<string>("all")

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
      const nr = r.risk ?? 0
      setRisk(nr)
      setRiskHistory(h=> [...h.slice(-19), nr])
      const t = await fetch(`${API}/api/cases/${cid}/timeline`).then(r=>r.json())
      setTimeline(t.timeline || [])
      const g = await fetch(`${API}/api/cases/${cid}/graph`).then(r=>r.json())
      setGraph(g)
      try{ const rp = await fetch(`${API}/api/cases/${cid}/reports`).then(x=>x.json()); setReports(rp.reports||[]) }catch{}
      try{ const sr = await fetch(`${API}/api/sigma/rules`).then(x=>x.json()); setSigmaRules(sr.rules||[]) }catch{}
      const cs = await fetch(`${API}/api/cases`).then(r=>r.json())
      setCases(cs.cases||[])
      // auto-create case 1 if no cases yet (for demo)
      if((cs.cases||[]).length===0 && cid===1){
        try{ await fetch(`${API}/api/cases`,{method:'POST',headers:{'Content-Type':'application/json'},body: JSON.stringify({title: 'case-1'})}) }catch{}
      }
      const ev = await fetch(`${API}/api/evidence?case_id=${cid}`).then(r=>r.json())
      setEvidence(ev.evidence||[])
      const f = await fetch(`${API}/api/findings?case_id=${cid}`).then(r=>r.json())
      setFindings(f.findings||[])
    }catch(e){/* fallback keeps last values */}
  }

  const createCase = async ()=>{
    try{
      const res = await fetch(`${API}/api/cases`,{method:'POST',headers:{'Content-Type':'application/json'},body: JSON.stringify({title: `case-${cases.length+1}`})})
      const data = await res.json()
      const nid = data.id ?? data.case?.id ?? (cases.length+1)
      setCaseId(nid)
      setLastRun(`Created case ${nid}`)
      await refresh(nid)
    }catch(e:any){ setError(e.message||String(e)) }
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

  const [runPlatform, setRunPlatform] = useState<string>("linux")
  const [riskHistory, setRiskHistory] = useState<number[]>([0])
  const [selectedNode, setSelectedNode] = useState<string | null>(null)
  // Report history + Sigma per P0-2
  const [reports, setReports] = useState<any[]>([])
  const [sigmaRules, setSigmaRules] = useState<any[]>([])

  const runExecute = async ()=>{
    setLoading(true); setError("")
    try{
      const res = await fetch(`${API}/api/run`,{method:'POST',headers:{'Content-Type':'application/json'},body: JSON.stringify({source, agent_id:'WIN-001', host_id:'HOST-001', case_id: caseId, platform: runPlatform})})
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

  // Derived filters for evidence (case isolation + host/type/platform per FORENSICS §7, ARCHITECTURE §11)
  const hosts = Array.from(new Set(evidence.map((e:any)=> e.host_id || e.hostId || 'unknown')))
  const filteredEvidence = evidence.filter((e:any)=>{
    if(hostFilter!=="all" && e.host_id!==hostFilter) return false
    if(typeFilter!=="all" && e.type!==typeFilter) return false
    if(platformFilter!=="all" && (e.payload?.platform||'unknown')!==platformFilter) return false
    return true
  })

  return (
    <div className="min-h-screen p-6 bg-zinc-950 text-zinc-100">
      <header className="flex justify-between items-center border-b border-zinc-800 pb-4 mb-6">
        <h1 className="text-2xl font-bold">JOCKY Forensic Dashboard <span className="text-violet-400">L8 Correlation</span></h1>
        <span className="text-xs bg-zinc-900 px-3 py-1 rounded">Backend: {cases.length} cases • {evidence.length} evidence • IR v1 • YARA {yara?.yara_binary_used ? '✅ binary' : yara?.yara_available ? '✅ rules' : '⏳ fallback'} • Nginx 8082 • Postgres {yara? '✅' : ''} • MinIO+Redis {cases.length>0?'✅':''}</span>
      </header>

      {/* Case isolation bar — ARCHITECTURE §11 case management + FORENSICS §7 case isolation */}
      <div className="bg-zinc-900 rounded-xl p-3 border border-zinc-800 mb-4 flex flex-wrap gap-3 items-center">
        <span className="text-xs font-semibold">Case</span>
        <select value={caseId} onChange={e=> setCaseId(Number(e.target.value))} className="bg-zinc-950 border border-zinc-700 rounded px-2 py-1 text-sm">
          {cases.length===0 && <option value={caseId}>case-{caseId}</option>}
          {cases.map((c:any)=><option key={c.id} value={c.id}>case-{c.id} {c.title? `— ${c.title}`:''} (risk {c.risk})</option>)}
        </select>
        <button onClick={createCase} disabled={loading} className="text-xs bg-violet-600 hover:bg-violet-500 px-3 py-1 rounded">+ New Case</button>
        <span className="text-xs text-zinc-500 ml-2">Host</span>
        <select value={hostFilter} onChange={e=> setHostFilter(e.target.value)} className="bg-zinc-950 border border-zinc-700 rounded px-2 py-1 text-xs">
          <option value="all">all hosts ({hosts.length})</option>
          {hosts.map((h:string)=><option key={h} value={h}>{h}</option>)}
        </select>
        <span className="text-xs text-zinc-500">Type</span>
        <select value={typeFilter} onChange={e=> setTypeFilter(e.target.value)} className="bg-zinc-950 border border-zinc-700 rounded px-2 py-1 text-xs">
          <option value="all">all types</option>
          <option value="system">system</option>
          <option value="process">process</option>
          <option value="file">file</option>
          <option value="network">network</option>
          <option value="driver">driver</option>
        </select>
        <span className="text-xs text-zinc-500">Platform</span>
        <select value={platformFilter} onChange={e=> setPlatformFilter(e.target.value)} className="bg-zinc-950 border border-zinc-700 rounded px-2 py-1 text-xs">
          <option value="all">all</option>
          <option value="windows">windows</option>
          <option value="linux">linux</option>
        </select>
        <span className="text-xs text-zinc-500 ml-auto">{filteredEvidence.length}/{evidence.length} evidence in case {caseId}{hostFilter!=='all'||typeFilter!=='all'||platformFilter!=='all' ? ' (filtered)':''}</span>
      </div>

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
            <div className="flex gap-2 mt-2 flex-wrap items-center">
              <button onClick={runCompile} disabled={loading} className="bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 px-4 py-2 rounded text-sm disabled:opacity-50">Compile</button>
              <select value={runPlatform} onChange={e=> setRunPlatform(e.target.value)} className="bg-zinc-950 border border-zinc-700 rounded px-2 py-2 text-xs"><option value="linux">linux</option><option value="windows">windows</option></select>
              <button onClick={runExecute} disabled={loading} className="bg-violet-600 hover:bg-violet-500 px-4 py-2 rounded text-sm font-semibold disabled:opacity-50">Run ({runPlatform})</button>
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
          <p className="text-xs text-zinc-500 mb-2">Host → Evidence nodes (op/type) → Finding • MITRE {graph.mitre?.join(', ')||'T1055/T1068'} • {graph.nodes?.length||0} nodes {filteredEvidence.length}/{evidence.length} evidence {platformFilter!=='all' ? `· platform=${platformFilter}`:''} {selectedNode?`· selected ${selectedNode}`:''}</p>
          <Graph data={graph} onSelect={setSelectedNode} />
          {selectedNode && <div className="mt-2 text-xs bg-zinc-950 p-2 rounded border border-violet-700">Selected: <span className="text-violet-400">{selectedNode}</span> {(() => { const ev = evidence.find((x:any)=> x.id===selectedNode); if(ev){ const p=ev.payload||{}; return `· ${ev.type} risk ${ev.risk} · ${p.mitre||''} ${p.platform||''} ` } return `— finding/host` })()} <button onClick={async()=>{ try{ const r=await fetch(`${API}/api/cases/${caseId}/graph/expand?node_id=${selectedNode}`).then(x=>x.json()); alert(JSON.stringify(r).slice(0,600)) }catch{}} } className="ml-2 underline">expand</button> <button onClick={()=> setSelectedNode(null)} className="ml-2 underline">clear</button></div>}
          {evidence.length>0 && <div className="mt-3 text-xs"><div className="font-semibold mb-1">Evidence store (case {caseId}) — canonical envelope schema_version 1 + integrity SHA256 {filteredEvidence.length!==evidence.length?`· filtered ${filteredEvidence.length}/${evidence.length}`:''}:</div>
            <div className="space-y-1 max-h-52 overflow-auto bg-zinc-950 p-2 rounded border border-zinc-800">
              {filteredEvidence.slice(-8).map((e:any)=>{
                const p=e.payload||{}
                const detail = e.type==='process' ? `${p.count} procs${p.processes?.some((x:any)=>x.ppid_anomaly)?' • ppid anomaly':''}${p.platform?` · ${p.platform}`:''}` :
                  e.type==='file' ? `${p.path} ${p.hashes?.sha256?.slice(0,12)??''} ${p.yara_hit?'• YARA':''}${p.platform?` · ${p.platform}`:''}` :
                  e.type==='network' ? `${p.connections?.length} conns ${p.connections?.some((c:any)=>c.remote_address==='192.0.2.20')?'• C2':''}${p.platform?` · ${p.platform}`:''}` :
                  JSON.stringify(p).slice(0,80)
                return <div key={e.id} className="font-mono text-xs"><span className="text-violet-400">{e.id}</span> {e.op} host {e.host_id} risk {e.risk} • {detail}</div>
              })}
            </div>
          </div>}
        </div>
        <div className="col-span-4 space-y-4">
          <RiskGauge risk={risk} history={riskHistory} />
          {/* Report history — P0-2 per FORENSICS §64 */}
          <div className="bg-zinc-900 rounded-xl p-4 border border-zinc-800">
            <h3 className="font-semibold flex justify-between items-center">Reports — History <span className="text-xs bg-zinc-800 px-2 py-1 rounded">{reports.length}</span></h3>
            {reports.length===0 ? <p className="text-xs text-zinc-500 mt-2">No reports yet — Run then Download PDF, history appears here.</p> :
              <ul className="mt-2 space-y-1 max-h-40 overflow-auto">{reports.map((r:any)=><li key={r.key} className="text-xs flex justify-between bg-zinc-950 p-1 rounded border border-zinc-800"><span className="truncate mono">{r.key.split('/').pop()}</span><button onClick={async()=>{ const res=await fetch(`${API}/api/cases/${caseId}/reports/${r.key.split('/').pop()}`); const b=await res.blob(); const u=URL.createObjectURL(b); const a=document.createElement('a'); a.href=u; a.download=r.key.split('/').pop(); document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(u) }} className="text-violet-400 underline ml-2">dl</button></li>)}</ul>}
            <div className="text-xs text-zinc-500 mt-1"><a className="underline" href={`${API}/api/cases/${caseId}/reports`} target="_blank">/reports</a></div>
          </div>
          {/* Sigma rules — P0-2 per ARCHITECTURE §13 */}
          <div className="bg-zinc-900 rounded-xl p-4 border border-zinc-800">
            <h3 className="font-semibold">Sigma Rules — Tune</h3>
            {sigmaRules.length===0 ? <p className="text-xs text-zinc-500 mt-2">No rules — check /api/sigma/rules</p> :
              <ul className="mt-2 space-y-1">{sigmaRules.map((r:any)=><li key={r.id} className="text-xs flex justify-between bg-zinc-950 p-2 rounded border border-zinc-800"><span><span className="text-violet-400">{r.id}</span> {r.level} {r.mitre} conf {(r.confidence??0.8).toFixed(2)} {r.tuned?'· tuned':''}</span><button onClick={async()=>{ const v=prompt(`New confidence for ${r.id} (0.5-0.95)`); if(!v) return; await fetch(`${API}/api/sigma/tune`,{method:'POST',headers:{'Content-Type':'application/json'},body: JSON.stringify({rule_id:r.id, confidence:Number(v)})}); const jr=await fetch(`${API}/api/sigma/rules`).then(x=>x.json()); setSigmaRules(jr.rules||[]) }} className="text-xs bg-zinc-800 px-2 py-1 rounded">tune</button></li>)}</ul>}
            <button onClick={async()=>{ await fetch(`${API}/api/sigma/auto-tune`,{method:'POST'}); const jr=await fetch(`${API}/api/sigma/rules`).then(x=>x.json()); setSigmaRules(jr.rules||[]) }} className="text-xs mt-2 bg-amber-600 hover:bg-amber-500 px-3 py-1 rounded">Auto-Tune (hit-rate)</button>
            <div className="text-xs text-zinc-500 mt-1"><a className="underline" href={`${API}/api/sigma/rules`} target="_blank">/sigma/rules</a> · <a className="underline" href={`${API}/api/sigma/status`} target="_blank">/sigma/status</a></div>
          </div>
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
