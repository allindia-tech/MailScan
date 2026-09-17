/**
 * MailTrace Workstation - Entity Relationship Threat Graph
 * Source of Truth: ref/DESIGN.md & ref/code.html
 * Visualizes correlated hops, domain bindings, URL payloads, and IOCs with forensic node inspection.
 */

import React, { useState } from 'react';
import {
  GitGraph,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  Server,
  Mail,
  Globe,
  Link2,
  FileCode,
  Layers,
  ShieldAlert,
  Share2,
  Terminal,
  FileText
} from 'lucide-react';
import { EmailAnalysisResult, GraphNode } from '../types/forensics.js';

interface RelationshipGraphViewProps {
  analysis: EmailAnalysisResult;
}

export const RelationshipGraphView: React.FC<RelationshipGraphViewProps> = ({ analysis }) => {
  const [selectedNodeId, setSelectedNodeId] = useState<string>('node-email-root');
  const [zoom, setZoom] = useState<number>(1);
  const [pan, setPan] = useState<{ x: number; y: number }>({ x: 0, y: 0 });

  const { graph } = analysis;
  const selectedNode = graph.nodes.find(n => n.id === selectedNodeId) || graph.nodes[0];

  const getNodeColor = (risk: GraphNode['risk']) => {
    switch (risk) {
      case 'CRITICAL':
        return { border: '#e11d48', bg: '#fff1f2', text: '#9f1239', badge: 'CRITICAL' };
      case 'HIGH':
        return { border: '#d97706', bg: '#fffbeb', text: '#92400e', badge: 'HIGH' };
      case 'MEDIUM':
        return { border: '#3b82f6', bg: '#eff6ff', text: '#1e40af', badge: 'MEDIUM' };
      default:
        return { border: '#94a3b8', bg: '#f8fafc', text: '#475569', badge: 'LOW' };
    }
  };

  return (
    <div className="space-y-5">
      
      {/* Top Toolbar */}
      <div className="rounded-xl bg-white border border-slate-200 shadow-xs p-3.5 flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <GitGraph className="w-4 h-4 text-indigo-600" />
          <div>
            <h2 className="text-xs uppercase tracking-wider font-bold text-slate-900 font-mono">
              Entity Threat Correlation Graph
            </h2>
            <span className="text-[11px] text-slate-500">
              {graph.nodes.length} entities &bull; {graph.edges.length} correlated hops and infrastructure bindings
            </span>
          </div>
        </div>

        {/* Zoom & Reset Controls */}
        <div className="flex items-center gap-1.5 bg-slate-50 p-1 rounded border border-slate-200">
          <button
            onClick={() => setZoom(z => Math.min(1.6, z + 0.15))}
            className="p-1 rounded text-slate-600 hover:text-slate-900 hover:bg-white transition"
            title="Zoom in"
          >
            <ZoomIn className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() => setZoom(z => Math.max(0.6, z - 0.15))}
            className="p-1 rounded text-slate-600 hover:text-slate-900 hover:bg-white transition"
            title="Zoom out"
          >
            <ZoomOut className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() => { setZoom(1); setPan({ x: 0, y: 0 }); }}
            className="p-1 rounded text-slate-600 hover:text-slate-900 hover:bg-white transition"
            title="Reset"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Main Canvas & Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        
        {/* SVG Node-Link Canvas */}
        <div className="lg:col-span-8 rounded-xl bg-slate-50 border border-slate-200 shadow-xs p-4 h-[540px] relative overflow-hidden flex items-center justify-center select-none">
          <svg
            viewBox="0 0 800 760"
            className="w-full h-full cursor-default"
            style={{
              transform: `scale(${zoom}) translate(${pan.x}px, ${pan.y}px)`,
              transformOrigin: 'center center',
              transition: 'transform 0.12s ease-out'
            }}
          >
            <defs>
              <marker
                id="edge-arrow"
                markerWidth="8"
                markerHeight="6"
                refX="14"
                refY="3"
                orient="auto"
              >
                <polygon points="0 0, 8 3, 0 6" fill="#94a3b8" />
              </marker>
            </defs>

            {/* Background grid dots */}
            <pattern id="dot-grid" width="24" height="24" patternUnits="userSpaceOnUse">
              <circle cx="12" cy="12" r="0.75" fill="#cbd5e1" />
            </pattern>
            <rect width="100%" height="100%" fill="url(#dot-grid)" />

            {/* Edges with relationship labels */}
            {graph.edges.map((edge) => {
              const src = graph.nodes.find(n => n.id === edge.source);
              const tgt = graph.nodes.find(n => n.id === edge.target);
              if (!src || !tgt || src.x === undefined || src.y === undefined || tgt.x === undefined || tgt.y === undefined) return null;

              const midX = (src.x + tgt.x) / 2;
              const midY = (src.y + tgt.y) / 2;

              return (
                <g key={edge.id}>
                  <line
                    x1={src.x}
                    y1={src.y}
                    x2={tgt.x}
                    y2={tgt.y}
                    stroke="#94a3b8"
                    strokeWidth="1.25"
                    strokeDasharray="4 3"
                    markerEnd="url(#edge-arrow)"
                  />
                  <rect
                    x={midX - 32}
                    y={midY - 8}
                    width="64"
                    height="16"
                    rx="3"
                    fill="#ffffff"
                    stroke="#e2e8f0"
                    strokeWidth="1"
                  />
                  <text
                    x={midX}
                    y={midY + 3.5}
                    textAnchor="middle"
                    fill="#475569"
                    fontSize="8.5"
                    fontFamily="monospace"
                  >
                    {edge.label}
                  </text>
                </g>
              );
            })}

            {/* Nodes */}
            {graph.nodes.map((node) => {
              const isSelected = node.id === selectedNodeId;
              const style = getNodeColor(node.risk);
              const posX = node.x || 100;
              const posY = node.y || 100;
              const nodeWidth = 140;
              const nodeHeight = 44;

              return (
                <g
                  key={node.id}
                  transform={`translate(${posX - nodeWidth / 2}, ${posY - nodeHeight / 2})`}
                  className="cursor-pointer"
                  onClick={() => setSelectedNodeId(node.id)}
                >
                  {isSelected && (
                    <rect
                      x="-3"
                      y="-3"
                      width={nodeWidth + 6}
                      height={nodeHeight + 6}
                      rx="6"
                      fill="none"
                      stroke="#4338ca"
                      strokeWidth="2"
                    />
                  )}

                  <rect
                    x="0"
                    y="0"
                    width={nodeWidth}
                    height={nodeHeight}
                    rx="4"
                    fill={style.bg}
                    stroke={isSelected ? '#4338ca' : style.border}
                    strokeWidth="1"
                  />

                  <rect
                    x="0"
                    y="0"
                    width="3"
                    height={nodeHeight}
                    rx="1"
                    fill={style.border}
                  />

                  <text
                    x="10"
                    y="15"
                    fill="#64748b"
                    fontSize="8.5"
                    fontFamily="monospace"
                    fontWeight="bold"
                  >
                    {node.type.toUpperCase()}
                  </text>

                  <text
                    x={nodeWidth - 8}
                    y="15"
                    textAnchor="end"
                    fill={style.text}
                    fontSize="8"
                    fontFamily="monospace"
                    fontWeight="bold"
                  >
                    {style.badge}
                  </text>

                  <text
                    x="10"
                    y="32"
                    fill="#0f172a"
                    fontSize="10"
                    fontFamily="monospace"
                    fontWeight="600"
                  >
                    {node.label.length > 18 ? `${node.label.slice(0, 16)}...` : node.label}
                  </text>
                </g>
              );
            })}
          </svg>
        </div>

        {/* Node Forensic Inspector Panel */}
        <div className="lg:col-span-4 rounded-xl bg-white border border-slate-200 shadow-xs p-4 flex flex-col justify-between">
          <div>
            <div className="pb-3 mb-3 border-b border-slate-100 flex items-center justify-between">
              <h3 className="text-xs uppercase tracking-wider font-bold text-slate-900 font-mono">
                Entity Forensic Inspector
              </h3>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-50 text-indigo-700 font-semibold border border-indigo-200">
                {selectedNode?.type?.toUpperCase() || 'NODE'}
              </span>
            </div>

            {selectedNode ? (
              <div className="space-y-3 text-xs">
                <div className="p-3 rounded bg-slate-50 border border-slate-200 space-y-1">
                  <div className="text-[10px] font-mono text-slate-500 uppercase font-bold">Entity Label</div>
                  <div className="font-mono text-xs font-bold text-slate-900 break-all">{selectedNode.label}</div>
                </div>

                <div className="p-3 rounded bg-slate-50 border border-slate-200 space-y-1">
                  <div className="text-[10px] font-mono text-slate-500 uppercase font-bold">Threat & Risk Score</div>
                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                      selectedNode.risk === 'CRITICAL'
                        ? 'bg-rose-50 text-rose-700 border-rose-200'
                        : selectedNode.risk === 'HIGH'
                        ? 'bg-amber-50 text-amber-800 border-amber-200'
                        : 'bg-emerald-50 text-emerald-700 border-emerald-200'
                    }`}>
                      {selectedNode.risk} RISK
                    </span>
                  </div>
                </div>

                {selectedNode.details && (
                  <div className="p-3 rounded bg-slate-50 border border-slate-200 space-y-1">
                    <div className="text-[10px] font-mono text-slate-500 uppercase font-bold">Forensic Telemetry Details</div>
                    <p className="text-slate-700 leading-relaxed text-xs">{selectedNode.details}</p>
                  </div>
                )}
              </div>
            ) : (
              <div className="py-8 text-center text-xs text-slate-500 font-mono">
                Click any node in the canvas to inspect forensic bindings.
              </div>
            )}
          </div>

          <div className="mt-4 pt-3 border-t border-slate-100 text-[11px] text-slate-500">
            Correlated entities link transport hops, IP addresses, domains, and cryptographic signatures.
          </div>
        </div>

      </div>

    </div>
  );
};
