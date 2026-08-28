import ReactFlow, { Background, Controls } from 'reactflow'
import 'reactflow/dist/style.css'
const nodes = [
  { id:'user', position:{x:0,y:0}, data:{label:'User: analyst'}, style:{background:'#27272a', color:'#fafafa', border:'1px solid #52525b'} },
  { id:'proc', position:{x:200,y:0}, data:{label:'explorer.exe (1234)\nHOLLOWED T1055'}, style:{background:'#7f1d1d', color:'#fecaca'} },
  { id:'file', position:{x:400,y:0}, data:{label:'suspicious.exe\nYARA HIT'}, style:{background:'#713f12', color:'#fef08a'} },
  { id:'net', position:{x:200,y:120}, data:{label:'185.220.101.5:443\nC2 ESTABLISHED'}, style:{background:'#1e1b4b', color:'#c4b5fd'} },
  { id:'drv', position:{x:400,y:120}, data:{label:'RTCore64.sys\nVULN T1068'}, style:{background:'#7f1d1d', color:'#fecaca'} },
  { id:'finding', position:{x:600,y:60}, data:{label:'Finding CRITICAL\nRisk 85/100'}, style:{background:'#dc2626', color:'#fff'} },
]
const edges = [
  { id:'e1', source:'user', target:'proc', label:'spawned' },
  { id:'e2', source:'proc', target:'file', label:'created' },
  { id:'e3', source:'proc', target:'net', label:'connected' },
  { id:'e4', source:'proc', target:'drv', label:'loaded' },
  { id:'e5', source:'file', target:'finding' },
  { id:'e6', source:'drv', target:'finding' },
  { id:'e7', source:'net', target:'finding' },
]
export default function Graph(){ return <div style={{height:300}}><ReactFlow nodes={nodes} edges={edges} fitView><Background/><Controls/></ReactFlow></div> }
