import ReactFlow, { Background, Controls } from 'reactflow'
import 'reactflow/dist/style.css'

const demoNodes = [
  { id:'user', position:{x:0,y:0}, data:{label:'User: analyst'}, style:{background:'#27272a', color:'#fafafa', border:'1px solid #52525b'} },
  { id:'proc', position:{x:200,y:0}, data:{label:'explorer.exe (1234)\nHOLLOWED T1055'}, style:{background:'#7f1d1d', color:'#fecaca'} },
  { id:'file', position:{x:400,y:0}, data:{label:'suspicious.exe\nYARA HIT'}, style:{background:'#713f12', color:'#fef08a'} },
  { id:'net', position:{x:200,y:120}, data:{label:'185.220.101.5:443\nC2 ESTABLISHED'}, style:{background:'#1e1b4b', color:'#c4b5fd'} },
  { id:'drv', position:{x:400,y:120}, data:{label:'RTCore64.sys\nVULN T1068'}, style:{background:'#7f1d1d', color:'#fecaca'} },
  { id:'finding', position:{x:600,y:60}, data:{label:'Finding CRITICAL\nRisk 85/100'}, style:{background:'#dc2626', color:'#fff'} },
]
const demoEdges = [
  { id:'e1', source:'user', target:'proc', label:'spawned' },
  { id:'e2', source:'proc', target:'file', label:'created' },
  { id:'e3', source:'proc', target:'net', label:'connected' },
  { id:'e4', source:'proc', target:'drv', label:'loaded' },
  { id:'e5', source:'file', target:'finding' },
  { id:'e6', source:'drv', target:'finding' },
  { id:'e7', source:'net', target:'finding' },
]

function toFlow(data:any){
  if(!data || !data.nodes || data.nodes.length===0) return {nodes: demoNodes, edges: demoEdges, isDemo:true}
  // map backend nodes to flow nodes with auto layout
  const nodes = data.nodes.map((n:any,i:number)=>{
    const x = (i%3)*200
    const y = Math.floor(i/3)*120
    const color = n.risk>60 ? '#7f1d1d' : n.risk>30 ? '#713f12' : '#27272a'
    const fg = n.risk>30 ? '#fecaca' : '#fafafa'
    return { id: String(n.id), position:{x,y}, data:{label: `${n.label||n.id}\n${n.type||''}`}, style:{background: color, color: fg, border:'1px solid #52525b', fontSize:'10px'} }
  })
  const edges = (data.edges||[]).map((e:any,i:number)=>({ id:`e${i}`, source:String(e.from||e.source), target:String(e.to||e.target), label: e.label||'' }))
  return {nodes, edges, isDemo:false}
}

export default function Graph({data}:{data?:any}){
  const flow = toFlow(data)
  return <div style={{height:320}}>
    {flow.isDemo && <div className="text-xs text-zinc-500 mb-1">Demo fallback — Run system.info(); to populate live graph</div>}
    <ReactFlow nodes={flow.nodes} edges={flow.edges} fitView><Background/><Controls/></ReactFlow>
  </div>
}
