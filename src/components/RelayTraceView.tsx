/**
 * MailTrace Workstation - SMTP Relay Path Reconstructor & Hop Geo-Trace
 * Source of Truth: ref/DESIGN.md & ref/code.html
 * Vertical node spine timeline with left status bar indicators and evidence-driven D3 map.
 */

import React, { useState, useMemo } from 'react';
import {
  MapPin,
  Clock,
  Server,
  Network,
  Globe,
  ArrowDown,
  Info,
  Shield,
  Radio,
  CheckCircle2,
  AlertTriangle,
  Terminal,
  Activity
} from 'lucide-react';
import { EmailAnalysisResult, RelayNode, ThreatLocation, ThreatRoute } from '../types/forensics.js';
import { GlobalThreatMap, isPlottableLocation } from './GlobalThreatMap.js';

interface RelayTraceViewProps {
  analysis: EmailAnalysisResult;
}

export const RelayTraceView: React.FC<RelayTraceViewProps> = ({ analysis }) => {
  const { relayPath, earliestReliableNode } = analysis;

  const [selectedNodeIndex, setSelectedNodeIndex] = useState<number>(
    earliestReliableNode ? earliestReliableNode.index : (relayPath[0]?.index ?? 1)
  );

  // Convert relayPath to ThreatLocation[] strictly for valid geographic nodes
  const mapLocations: ThreatLocation[] = useMemo(() => {
    return relayPath
      .filter(isPlottableLocation)
      .map((node, idx) => {
        const isEarliest = node.isEarliestReliable || (earliestReliableNode && node.index === earliestReliableNode.index);
        const isLast = idx === relayPath.length - 1;

        return {
          id: `hop-${node.index}`,
          latitude: node.lat,
          longitude: node.lon,
          type: isEarliest ? 'origin' : (isLast ? 'destination' : 'relay'),
          source: 'received-header',
          sourceId: `Received Header #${node.index}`,
          verified: true,
          precision: 'infrastructure_estimate',
          label: `Hop #${node.index}`,
          ip: node.ip,
          country: node.country,
          countryCode: node.countryCode,
          region: node.region,
          city: node.city,
          asn: node.asn,
          isp: node.isp,
          reverseDns: node.reverseDns,
          hostname: node.hostname,
          risk: node.reputation === 'CRITICAL' ? 90 : node.reputation === 'HIGH' ? 75 : node.reputation === 'MEDIUM' ? 45 : 10,
          confidence: node.confidence,
          timestamp: node.timestamp,
          isUntrustedBoundary: isEarliest,
          hopIndex: node.index,
          protocol: node.protocol,
          rawHeader: node.rawHeader
        };
      });
  }, [relayPath, earliestReliableNode]);

  // Convert pairs to ThreatRoute[] ONLY between hops that both have valid coordinates
  const mapRoutes: ThreatRoute[] = useMemo(() => {
    const routes: ThreatRoute[] = [];
    const plottableHops = relayPath.filter(isPlottableLocation);
    
    for (let i = 0; i < plottableHops.length - 1; i++) {
      const src = plottableHops[i];
      const dst = plottableHops[i + 1];
      routes.push({
        sourceId: `hop-${src.index}`,
        targetId: `hop-${dst.index}`,
        sourceCoords: [src.lon, src.lat],
        targetCoords: [dst.lon, dst.lat],
        confidence: src.confidence,
        hopNumber: src.index,
        label: `Hop ${src.index} → ${dst.index}`
      });
    }
    return routes;
  }, [relayPath]);

  const selectedNode: RelayNode = relayPath.find(n => n.index === selectedNodeIndex) || earliestReliableNode || relayPath[0] || {
    index: 1,
    ip: '127.0.0.1',
    hostname: 'localhost',
    reverseDns: 'unknown',
    timestamp: 'N/A',
    country: 'Unknown',
    countryCode: 'XX',
    region: 'Unknown',
    city: 'Unknown',
    lat: NaN,
    lon: NaN,
    isp: 'Unknown ISP',
    asn: 'AS0',
    organization: 'Unknown',
    confidence: 50,
    reputation: 'MEDIUM',
    isEarliestReliable: false,
    isUntrustedBoundary: false,
    protocol: 'ESMTPA',
    rawHeader: ''
  };

  const handleLocationSelect = (locId: string) => {
    const matched = mapLocations.find(l => l.id === locId);
    if (matched && matched.hopIndex !== undefined) {
      setSelectedNodeIndex(matched.hopIndex);
    }
  };

  return (
    <div className="space-y-5">
      
      {/* 1. Earliest Reliable Node Ingress Banner */}
      {earliestReliableNode && (
        <div className="rounded-xl bg-white border border-slate-200 shadow-xs p-4">
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-rose-50 text-rose-700 border border-rose-200 uppercase">
                  Untrusted Ingress Boundary
                </span>
                <span className="text-xs text-slate-500 font-mono">Hop #{earliestReliableNode.index}</span>
              </div>
              <h2 className="text-sm font-bold text-slate-900 flex flex-wrap items-center gap-2 font-mono">
                <span>Earliest Reliable Sender IP:</span>
                <span className="text-indigo-700">{earliestReliableNode.ip}</span>
                <span className="text-slate-600 font-sans font-normal text-xs">
                  ({earliestReliableNode.city && earliestReliableNode.city !== 'Unknown' ? `${earliestReliableNode.city}, ` : ''}{earliestReliableNode.country})
                </span>
              </h2>
              <p className="text-xs text-slate-600 mt-1">
                ISP: {earliestReliableNode.isp} &bull; ASN: <span className="font-mono text-slate-800">{earliestReliableNode.asn}</span> &bull; Reverse DNS: <span className="font-mono text-slate-800">{earliestReliableNode.reverseDns || 'None'}</span>
              </p>
            </div>

            <div className="text-xs text-slate-600 bg-slate-50 p-3 rounded-lg border border-slate-200 max-w-sm leading-normal">
              <strong className="text-slate-900">Boundary Verification: </strong>
              First external host handoff recorded by your organization's receiving mail gateway.
            </div>
          </div>
        </div>
      )}

      {/* 2. D3 Geolocation Map & Selected Infrastructure Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        
        {/* Left 8 Cols: Real D3 Natural Earth World Map */}
        <div className="lg:col-span-8 rounded-xl bg-white border border-slate-200 shadow-xs overflow-hidden p-4">
          <div className="flex items-center justify-between pb-3 mb-3 border-b border-slate-100">
            <div className="flex items-center gap-2">
              <Globe className="w-4 h-4 text-indigo-600" />
              <h3 className="text-xs uppercase font-bold text-slate-900 font-mono">
                Evidence-Driven Hop Geo-Trace Map
              </h3>
            </div>
            <span className="text-[11px] font-mono text-slate-500 bg-slate-50 px-2 py-0.5 rounded border border-slate-200">
              {mapLocations.length} Plottable Node(s)
            </span>
          </div>

          <GlobalThreatMap
            locations={mapLocations}
            routes={mapRoutes}
            selectedLocationId={`hop-${selectedNode.index}`}
            onLocationSelect={handleLocationSelect}
            showGlobalThreatLayer={false}
            threatActivities={[]}
            minHeight={380}
          />
        </div>

        {/* Right 4 Cols: Selected Infrastructure Panel */}
        <div className="lg:col-span-4 rounded-xl bg-white border border-slate-200 shadow-xs p-4 flex flex-col justify-between">
          <div>
            <div className="pb-3 mb-3 border-b border-slate-100 flex items-center justify-between">
              <h3 className="text-xs uppercase tracking-wider font-bold text-slate-900 font-mono">
                Selected Node Telemetry
              </h3>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-50 text-indigo-700 font-semibold border border-indigo-200">
                Hop #{selectedNode.index}
              </span>
            </div>

            <div className="space-y-2 text-xs">
              <div className="flex items-center justify-between py-1 border-b border-slate-100">
                <span className="text-slate-500 font-mono">IP Address</span>
                <span className="font-mono text-slate-900 font-bold">{selectedNode.ip}</span>
              </div>

              <div className="flex items-center justify-between py-1 border-b border-slate-100">
                <span className="text-slate-500 font-mono">Country</span>
                <span className="text-slate-800 font-medium">
                  {selectedNode.country} {selectedNode.city && selectedNode.city !== 'Unknown' ? `(${selectedNode.city})` : ''}
                </span>
              </div>

              <div className="flex items-center justify-between py-1 border-b border-slate-100">
                <span className="text-slate-500 font-mono">ISP / Provider</span>
                <span className="text-slate-800 truncate max-w-[170px]" title={selectedNode.isp}>{selectedNode.isp}</span>
              </div>

              <div className="flex items-center justify-between py-1 border-b border-slate-100">
                <span className="text-slate-500 font-mono">ASN</span>
                <span className="font-mono text-indigo-700 font-semibold">{selectedNode.asn}</span>
              </div>

              <div className="flex items-center justify-between py-1 border-b border-slate-100">
                <span className="text-slate-500 font-mono">Confidence</span>
                <span className="font-mono text-slate-900 font-bold">{selectedNode.confidence}%</span>
              </div>

              <div className="flex items-start justify-between py-1 border-b border-slate-100">
                <span className="text-slate-500 font-mono shrink-0">Reverse DNS</span>
                <span className="font-mono text-[11px] text-slate-700 break-all text-right">{selectedNode.reverseDns || 'No PTR record'}</span>
              </div>

              <div className="flex items-start justify-between py-1 border-b border-slate-100">
                <span className="text-slate-500 font-mono shrink-0">Hostname</span>
                <span className="font-mono text-[11px] text-slate-700 break-all text-right">{selectedNode.hostname}</span>
              </div>

              <div className="flex items-center justify-between py-1">
                <span className="text-slate-500 font-mono">Coordinates</span>
                <span className="font-mono text-slate-700 text-[11px]">
                  {Number.isFinite(selectedNode.lat) && Number.isFinite(selectedNode.lon)
                    ? `${selectedNode.lat.toFixed(4)}, ${selectedNode.lon.toFixed(4)}`
                    : 'Unmapped / Private RFC 1918'}
                </span>
              </div>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-100 text-[11px] text-slate-500">
            Click any node capsule below to synchronize telemetry inspection.
          </div>
        </div>

      </div>

      {/* 3. Chronological Vertical Timeline with Left Status Bars */}
      <div className="rounded-xl bg-white border border-slate-200 shadow-xs p-4 space-y-4">
        <div className="pb-3 border-b border-slate-100 flex items-center justify-between">
          <div>
            <h2 className="text-xs uppercase tracking-wider font-bold text-slate-900 font-mono">
              Chronological Relay Path & Timeline
            </h2>
            <span className="text-[11px] text-slate-500">
              Sequential SMTP handoffs from origin MTA to internal destination gateway
            </span>
          </div>
          <span className="text-xs text-slate-700 font-mono font-semibold bg-slate-100 px-2 py-0.5 rounded border border-slate-200">
            {relayPath.length} Total Hops
          </span>
        </div>

        <div className="space-y-3 relative pl-6 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-200">
          {relayPath.map((node) => {
            const isSelected = node.index === selectedNodeIndex;
            const isEarliest = node.isEarliestReliable || (earliestReliableNode && node.index === earliestReliableNode.index);
            const isCrit = node.reputation === 'CRITICAL' || node.isTor;

            return (
              <div
                key={node.index}
                onClick={() => setSelectedNodeIndex(node.index)}
                className={`relative p-3.5 rounded-lg border cursor-pointer transition-all ${
                  isSelected
                    ? 'bg-indigo-50/60 border-indigo-400 shadow-xs ring-1 ring-indigo-500/20'
                    : 'bg-white border-slate-200 hover:border-slate-300 hover:bg-slate-50'
                }`}
                style={{
                  borderLeftWidth: '4px',
                  borderLeftColor: isCrit ? '#e11d48' : isEarliest ? '#d97706' : '#059669'
                }}
              >
                {/* Node Bullet Marker on spine */}
                <div className={`absolute -left-[27px] top-4 w-3.5 h-3.5 rounded-full border-2 bg-white ${
                  isCrit ? 'border-rose-500' : isEarliest ? 'border-amber-500' : 'border-emerald-500'
                }`} />

                <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-mono text-xs font-bold text-slate-900">
                      Hop #{node.index}: {node.ip}
                    </span>
                    <span className="text-slate-600 text-xs">
                      ({node.city && node.city !== 'Unknown' ? `${node.city}, ` : ''}{node.country})
                    </span>
                    {isEarliest && (
                      <span className="px-1.5 py-0.2 rounded text-[10px] font-mono font-bold bg-amber-50 text-amber-800 border border-amber-200">
                        Untrusted Boundary
                      </span>
                    )}
                    {node.isTor && (
                      <span className="px-1.5 py-0.2 rounded text-[10px] font-mono font-bold bg-rose-50 text-rose-700 border border-rose-200">
                        Tor Node
                      </span>
                    )}
                  </div>

                  <div className="text-[11px] font-mono text-slate-500">
                    {node.timestamp || 'Recorded Ingress'}
                  </div>
                </div>

                <div className="mt-1 text-xs text-slate-600 flex items-center gap-3 flex-wrap">
                  <span>ISP: <strong className="text-slate-800">{node.isp}</strong></span>
                  <span>&bull;</span>
                  <span>ASN: <strong className="font-mono text-slate-800">{node.asn}</strong></span>
                  <span>&bull;</span>
                  <span>rDNS: <code className="text-slate-700">{node.reverseDns || 'None'}</code></span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

    </div>
  );
};
