/**
 * MailTrace Workstation - SMTP Relay Path Reconstructor & Hop Geo-Trace
 * =======================================================================
 * Evidence-driven forensic reconstruction of RFC 5321/5322 SMTP handoffs,
 * untrusted ingress boundary isolation, and verified infrastructure telemetry.
 * Strictly zero synthetic coordinates.
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
  Activity,
  ShieldAlert,
  HelpCircle
} from 'lucide-react';
import { EmailAnalysisResult, RelayNode, ThreatLocation, ThreatRoute } from '../types/forensics.js';
import { GlobalThreatMap, isPlottableLocation } from './GlobalThreatMap.js';

interface RelayTraceViewProps {
  analysis: EmailAnalysisResult;
}

export const RelayTraceView: React.FC<RelayTraceViewProps> = ({ analysis }) => {
  const { relayPath = [], earliestReliableNode } = analysis;

  const [selectedNodeIndex, setSelectedNodeIndex] = useState<number>(
    earliestReliableNode ? earliestReliableNode.index : (relayPath[0]?.index ?? 1)
  );

  // Mappable Locations Filter: strictly requires valid numbers and public routability
  const mapLocations: ThreatLocation[] = useMemo(() => {
    return relayPath
      .filter(node => isPlottableLocation(node) && node.isPublic !== false)
      .map((node, idx) => {
        const isEarliest = node.isEarliestReliable || (earliestReliableNode && node.index === earliestReliableNode.index);
        const isLast = idx === relayPath.length - 1;

        return {
          id: `hop-${node.index}`,
          latitude: node.lat,
          longitude: node.lon,
          type: isEarliest ? 'origin' : (isLast ? 'destination' : 'relay'),
          source: (node.evidenceSource as any) || 'received-header',
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

  // Valid geographic routes between consecutive plottable hops
  const mapRoutes: ThreatRoute[] = useMemo(() => {
    const routes: ThreatRoute[] = [];
    const plottableHops = relayPath.filter(node => isPlottableLocation(node) && node.isPublic !== false);
    
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

  // Selected node resolution without synthetic fallback
  const selectedNode: RelayNode | undefined = useMemo(() => {
    if (relayPath.length === 0) return undefined;
    return relayPath.find(n => n.index === selectedNodeIndex) || earliestReliableNode || relayPath[0];
  }, [relayPath, selectedNodeIndex, earliestReliableNode]);

  const publicHops = useMemo(() => relayPath.filter(n => n.isPublic === true), [relayPath]);
  const privateHops = useMemo(() => relayPath.filter(n => n.isPublic === false), [relayPath]);

  const handleLocationSelect = (locId: string) => {
    const matched = mapLocations.find(l => l.id === locId);
    if (matched && matched.hopIndex !== undefined) {
      setSelectedNodeIndex(matched.hopIndex);
    }
  };

  // State 1: No Relay / Received Headers Available
  if (relayPath.length === 0) {
    return (
      <div className="space-y-5">
        <div className="rounded-xl bg-white border border-slate-200 shadow-xs p-8 text-center max-w-2xl mx-auto">
          <div className="w-12 h-12 rounded-full bg-slate-100 flex items-center justify-center mx-auto mb-4 text-slate-500">
            <Server className="w-6 h-6" />
          </div>
          <h3 className="text-base font-bold text-slate-900 font-mono mb-2">
            No Received Headers Available
          </h3>
          <p className="text-xs text-slate-600 leading-relaxed max-w-lg mx-auto">
            This email specimen does not contain standard RFC 5322 <code className="bg-slate-100 px-1.5 py-0.5 rounded font-mono text-slate-800">Received:</code> headers or secondary relay metadata (<code className="bg-slate-100 px-1.5 py-0.5 rounded font-mono text-slate-800">X-Originating-IP</code>, <code className="bg-slate-100 px-1.5 py-0.5 rounded font-mono text-slate-800">Received-SPF</code>).
          </p>
          <div className="mt-5 p-3 rounded-lg bg-amber-50 border border-amber-200 text-amber-800 text-xs text-left max-w-md mx-auto">
            <div className="font-semibold flex items-center gap-1.5 mb-1">
              <Info className="w-3.5 h-3.5" /> Forensic Note
            </div>
            To reconstruct the multi-hop transport path and geolocate network infrastructure, please analyze an email containing full transport headers.
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      
      {/* 1. Ingress Boundary Banner */}
      {earliestReliableNode && (
        <div className="rounded-xl bg-white border border-slate-200 shadow-xs p-4">
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-amber-50 text-amber-800 border border-amber-200 uppercase">
                  {earliestReliableNode.isPublic ? 'Untrusted Ingress Boundary' : 'Earliest Observable Hop'}
                </span>
                <span className="text-xs text-slate-500 font-mono">Hop #{earliestReliableNode.index} of {relayPath.length}</span>
              </div>
              <h2 className="text-sm font-bold text-slate-900 flex flex-wrap items-center gap-2 font-mono">
                <span>Earliest Observable Public Node:</span>
                <span className="text-indigo-700">{earliestReliableNode.ip}</span>
                <span className="text-slate-600 font-sans font-normal text-xs">
                  ({earliestReliableNode.city && earliestReliableNode.city !== 'Unknown' && earliestReliableNode.city !== 'Non-Routable' ? `${earliestReliableNode.city}, ` : ''}{earliestReliableNode.country})
                </span>
              </h2>
              <p className="text-xs text-slate-600 mt-1">
                ISP: <strong className="text-slate-800">{earliestReliableNode.isp}</strong> &bull; ASN: <span className="font-mono text-slate-800 font-bold">{earliestReliableNode.asn}</span> &bull; Reverse DNS: <span className="font-mono text-slate-800">{earliestReliableNode.reverseDns || 'None'}</span>
              </p>
            </div>

            <div className="text-xs text-slate-600 bg-slate-50 p-3 rounded-lg border border-slate-200 max-w-sm leading-normal">
              <strong className="text-slate-900">Boundary Verification: </strong>
              {earliestReliableNode.isPublic 
                ? "First external public host handoff recorded by your organization's receiving mail gateway."
                : "All observed hops represent internal, private, or loopback network infrastructure."}
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
            <div className="flex items-center gap-2">
              <span className="text-[11px] font-mono text-slate-600 bg-slate-50 px-2 py-0.5 rounded border border-slate-200">
                {mapLocations.length} Plottable Node(s)
              </span>
              <span className="text-[11px] font-mono text-slate-600 bg-slate-50 px-2 py-0.5 rounded border border-slate-200">
                {relayPath.length} Total Hop(s)
              </span>
            </div>
          </div>

          {mapLocations.length === 0 ? (
            <div className="p-8 rounded-lg bg-slate-50 border border-slate-200 text-center my-4">
              <div className="w-10 h-10 rounded-full bg-slate-200 flex items-center justify-center mx-auto mb-3 text-slate-600">
                <MapPin className="w-5 h-5 text-slate-400" />
              </div>
              <h4 className="text-xs font-bold text-slate-800 font-mono mb-1">
                {publicHops.length === 0
                  ? 'No Mappable Public Infrastructure'
                  : 'Public Hops Detected (Coordinates Unverified)'}
              </h4>
              <p className="text-xs text-slate-500 max-w-md mx-auto">
                {publicHops.length === 0
                  ? 'Observed relay hops consist entirely of local, loopback (127.0.0.1), or private (RFC 1918) network addresses which are not Internet-routable.'
                  : 'Public IP addresses were extracted from headers, but verified geographic coordinates are not available from the intelligence provider.'}
              </p>
            </div>
          ) : (
            <GlobalThreatMap
              locations={mapLocations}
              routes={mapRoutes}
              selectedLocationId={selectedNode ? `hop-${selectedNode.index}` : undefined}
              onLocationSelect={handleLocationSelect}
              showGlobalThreatLayer={false}
              threatActivities={[]}
              minHeight={380}
            />
          )}

          {/* Forensic Disclaimer */}
          <div className="mt-3 pt-2 border-t border-slate-100 flex items-start gap-2 text-[11px] text-slate-500">
            <Info className="w-3.5 h-3.5 text-slate-400 shrink-0 mt-0.5" />
            <span>
              <strong>Forensic Disclaimer:</strong> Geolocation markers represent verified network infrastructure locations. They do not establish the physical location or identity of a human actor.
            </span>
          </div>
        </div>

        {/* Right 4 Cols: Selected Infrastructure Panel */}
        <div className="lg:col-span-4 rounded-xl bg-white border border-slate-200 shadow-xs p-4 flex flex-col justify-between">
          {selectedNode ? (
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
                  <span className="text-slate-500 font-mono">Classification</span>
                  <span className={`font-mono text-[11px] px-1.5 py-0.5 rounded font-bold ${
                    selectedNode.isPublic
                      ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                      : 'bg-slate-100 text-slate-700 border border-slate-200'
                  }`}>
                    {selectedNode.classification || (selectedNode.isPublic ? 'PUBLIC' : 'PRIVATE / LOOPBACK')}
                  </span>
                </div>

                <div className="flex items-center justify-between py-1 border-b border-slate-100">
                  <span className="text-slate-500 font-mono">Country</span>
                  <span className="text-slate-800 font-medium">
                    {selectedNode.country} {selectedNode.city && selectedNode.city !== 'Unknown' && selectedNode.city !== 'Non-Routable' ? `(${selectedNode.city})` : ''}
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
                      : selectedNode.isPublic ? 'Coordinates Unverified' : 'Not Mappable (Private / Loopback)'}
                  </span>
                </div>
              </div>
            </div>
          ) : (
            <div className="text-center py-12 text-slate-400 text-xs font-mono">
              No node selected
            </div>
          )}

          <div className="mt-4 pt-3 border-t border-slate-100 text-[11px] text-slate-500">
            Click any node in the timeline below to inspect forensic telemetry.
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
            const isSelected = selectedNode && node.index === selectedNode.index;
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
                  borderLeftColor: isCrit ? '#e11d48' : isEarliest ? '#d97706' : (node.isPublic ? '#059669' : '#64748b')
                }}
              >
                {/* Node Bullet Marker on spine */}
                <div className={`absolute -left-[27px] top-4 w-3.5 h-3.5 rounded-full border-2 bg-white ${
                  isCrit ? 'border-rose-500' : isEarliest ? 'border-amber-500' : (node.isPublic ? 'border-emerald-500' : 'border-slate-400')
                }`} />

                <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-mono text-xs font-bold text-slate-900">
                      Hop #{node.index}: {node.ip}
                    </span>
                    <span className="text-slate-600 text-xs">
                      ({node.city && node.city !== 'Unknown' && node.city !== 'Non-Routable' ? `${node.city}, ` : ''}{node.country})
                    </span>
                    {isEarliest && (
                      <span className="px-1.5 py-0.2 rounded text-[10px] font-mono font-bold bg-amber-50 text-amber-800 border border-amber-200">
                        {node.isPublic ? 'Untrusted Boundary' : 'Earliest Hop'}
                      </span>
                    )}
                    {!node.isPublic && (
                      <span className="px-1.5 py-0.2 rounded text-[10px] font-mono font-bold bg-slate-100 text-slate-700 border border-slate-200">
                        {node.classification || 'Private / Local'}
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
                  {node.protocol && (
                    <>
                      <span>&bull;</span>
                      <span className="font-mono text-[11px] text-indigo-700 bg-indigo-50 px-1.5 py-0.2 rounded border border-indigo-100">
                        {node.protocol}
                      </span>
                    </>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* 4. Forensic Relay Evidence Table */}
      <div className="rounded-xl bg-white border border-slate-200 shadow-xs p-4 space-y-3">
        <div className="pb-2 border-b border-slate-100 flex items-center justify-between">
          <h3 className="text-xs uppercase tracking-wider font-bold text-slate-900 font-mono flex items-center gap-2">
            <Terminal className="w-4 h-4 text-indigo-600" />
            Relay Forensic Evidence Audit Table
          </h3>
          <span className="text-[11px] text-slate-500 font-mono">
            {publicHops.length} Public / {privateHops.length} Private
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50/75 text-slate-700 font-mono">
                <th className="py-2 px-3 font-semibold">Hop</th>
                <th className="py-2 px-3 font-semibold">IP Address</th>
                <th className="py-2 px-3 font-semibold">Classification</th>
                <th className="py-2 px-3 font-semibold">Evidence Source</th>
                <th className="py-2 px-3 font-semibold">Location / Network</th>
                <th className="py-2 px-3 font-semibold">Geo Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 font-sans">
              {relayPath.map((hop) => {
                const isPlottable = Number.isFinite(hop.lat) && Number.isFinite(hop.lon);

                return (
                  <tr 
                    key={hop.index}
                    onClick={() => setSelectedNodeIndex(hop.index)}
                    className={`cursor-pointer hover:bg-slate-50 transition-colors ${
                      selectedNode && selectedNode.index === hop.index ? 'bg-indigo-50/40' : ''
                    }`}
                  >
                    <td className="py-2 px-3 font-mono font-bold text-slate-900">
                      #{hop.index}
                    </td>
                    <td className="py-2 px-3 font-mono text-slate-800">
                      {hop.ip}
                    </td>
                    <td className="py-2 px-3">
                      <span className={`px-1.5 py-0.5 rounded font-mono text-[10px] font-bold ${
                        hop.isPublic
                          ? 'bg-emerald-50 text-emerald-800 border border-emerald-200'
                          : 'bg-slate-100 text-slate-700 border border-slate-200'
                      }`}>
                        {hop.classification || (hop.isPublic ? 'PUBLIC' : 'PRIVATE')}
                      </span>
                    </td>
                    <td className="py-2 px-3 font-mono text-[11px] text-slate-600">
                      {hop.evidenceSource || 'received-header'}
                    </td>
                    <td className="py-2 px-3 text-slate-700">
                      {hop.city && hop.city !== 'Unknown' && hop.city !== 'Non-Routable' ? `${hop.city}, ` : ''}{hop.country} ({hop.isp})
                    </td>
                    <td className="py-2 px-3">
                      {isPlottable ? (
                        <span className="inline-flex items-center gap-1 font-mono text-[10px] font-bold text-emerald-700 bg-emerald-50 px-1.5 py-0.5 rounded border border-emerald-200">
                          <CheckCircle2 className="w-3 h-3" />
                          Plotted [{hop.lat.toFixed(2)}, {hop.lon.toFixed(2)}]
                        </span>
                      ) : hop.isPublic ? (
                        <span className="inline-flex items-center gap-1 font-mono text-[10px] text-slate-600 bg-slate-100 px-1.5 py-0.5 rounded border border-slate-200">
                          Coordinates Unavailable
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 font-mono text-[10px] text-slate-500 bg-slate-50 px-1.5 py-0.5 rounded border border-slate-200">
                          Non-Mappable ({hop.classification || 'Private'})
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

    </div>
  );
};
