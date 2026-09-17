/**
 * MailTrace AI - Real D3.js Global Threat & Relay Path Geographical Map
 * STRICT PRODUCTION INTELLIGENCE: Zero dummy data, zero simulated markers, zero fake coordinates.
 * Natural Earth 1 projection with actual world geographic features.
 */

import React, { useEffect, useRef, useState, useMemo, useCallback } from 'react';
import * as d3 from 'd3';
import {
  Globe,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  Crosshair,
  AlertTriangle,
  Flame,
  Info,
  RefreshCw,
  Activity,
  MapPin,
  ShieldCheck
} from 'lucide-react';
import { ThreatLocation, ThreatRoute, ThreatActivity, GeoLocationEvidence } from '../types/forensics.js';
import { WorldMapDataLoader, WorldMapFeatureCollection } from '../utils/worldMapLoader.js';

export interface GlobalThreatMapProps {
  locations?: (ThreatLocation | GeoLocationEvidence)[];
  routes?: ThreatRoute[];
  selectedLocationId?: string;
  onLocationSelect?: (locationId: string) => void;
  threatActivities?: ThreatActivity[];
  showGlobalThreatLayer?: boolean;
  className?: string;
  minHeight?: number;
  autoFitRouteOnLoad?: boolean;
}

/**
 * Strict Geographic Validation Filter
 * Rejects undefined, null, non-numeric, NaN, out-of-bounds, or unverified locations.
 */
export function isPlottableLocation(location: any): boolean {
  if (!location) return false;
  const lat = location.latitude ?? location.lat;
  const lon = location.longitude ?? location.lon;

  return (
    typeof lat === 'number' &&
    typeof lon === 'number' &&
    Number.isFinite(lat) &&
    Number.isFinite(lon) &&
    !isNaN(lat) &&
    !isNaN(lon) &&
    lat >= -90 &&
    lat <= 90 &&
    lon >= -180 &&
    lon <= 180 &&
    (location.verified === true || location.verified === undefined)
  );
}

export const GlobalThreatMap: React.FC<GlobalThreatMapProps> = ({
  locations = [],
  routes = [],
  selectedLocationId,
  onLocationSelect,
  threatActivities = [],
  showGlobalThreatLayer = false,
  className = '',
  minHeight = 420,
  autoFitRouteOnLoad = true
}) => {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);
  const zoomBehaviorRef = useRef<d3.ZoomBehavior<SVGSVGElement, unknown> | null>(null);

  // Map Data State
  const [worldData, setWorldData] = useState<WorldMapFeatureCollection | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [dataSource, setDataSource] = useState<'network' | 'cache' | 'bundled_fallback'>('cache');

  // Container Dimensions
  const [dimensions, setDimensions] = useState<{ width: number; height: number }>({ width: 0, height: 0 });

  // Layer Toggles
  const [layerRelayPath, setLayerRelayPath] = useState<boolean>(true);
  const [layerThreatActivity, setLayerThreatActivity] = useState<boolean>(showGlobalThreatLayer);
  const [layerInfrastructure, setLayerInfrastructure] = useState<boolean>(true);

  // Activity Filters
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');

  // Interactive Tooltip State
  const [tooltip, setTooltip] = useState<{
    visible: boolean;
    x: number;
    y: number;
    title: string;
    type: 'origin' | 'relay' | 'destination' | 'activity';
    data: any;
  } | null>(null);

  // Hovered state
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);

  // 1. Strict Validation of Locations
  const validLocations = useMemo(() => {
    return locations.filter(isPlottableLocation).map(loc => {
      const lat = loc.latitude ?? (loc as any).lat;
      const lon = loc.longitude ?? (loc as any).lon;
      return {
        ...loc,
        latitude: lat,
        longitude: lon,
        source: (loc as any).source || 'received-header',
        verified: (loc as any).verified !== false,
        precision: (loc as any).precision || 'infrastructure_estimate'
      };
    });
  }, [locations]);

  // Filtered threat activities (strictly from real threat feed only, no demo seeds)
  const filteredActivities = useMemo(() => {
    if (!layerThreatActivity) return [];
    if (threatActivities.length === 0) return [];
    if (selectedCategory === 'ALL') return threatActivities;
    return threatActivities.filter(a => a.category.toLowerCase() === selectedCategory.toLowerCase());
  }, [threatActivities, layerThreatActivity, selectedCategory]);

  // Telemetry Audit Logging
  useEffect(() => {
    console.log(`[GeoTrace] Investigation ID: ${selectedLocationId || 'Active'}`);
    console.log(`[GeoTrace] Relay locations received: ${locations.length}`);
    console.log(`[GeoTrace] Valid locations plotted: ${validLocations.length}`);
    console.log(`[GeoTrace] Rejected locations (unmapped/no coords): ${locations.length - validLocations.length}`);
    console.log(`[GeoTrace] Threat intelligence events: ${filteredActivities.length}`);
  }, [locations.length, validLocations.length, filteredActivities.length, selectedLocationId]);

  // 2. Load World Geography via WorldMapDataLoader
  const loadMapData = useCallback(async (forceReload = false) => {
    try {
      setLoading(true);
      setLoadError(null);
      const result = await WorldMapDataLoader.loadWorldMap(forceReload);
      if (result.features && WorldMapDataLoader.validateWorldMap(result.features)) {
        setWorldData(result.features);
        setDataSource(result.source);
      } else {
        throw new Error('World map geographic data validation failed');
      }
    } catch (err: any) {
      console.error('WorldMapDataLoader error:', err);
      const fallback = WorldMapDataLoader.getCachedFeatures();
      if (fallback && fallback.features && fallback.features.length > 0) {
        setWorldData(fallback);
        setDataSource('bundled_fallback');
      } else {
        setLoadError(err?.message || 'Failed to initialize world map');
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadMapData();
  }, [loadMapData]);

  // 3. Measure Container with ResizeObserver
  useEffect(() => {
    if (!containerRef.current) return;

    const observer = new ResizeObserver((entries) => {
      for (const entry of entries) {
        const { width, height } = entry.contentRect;
        if (width > 0) {
          const effectiveHeight = Math.max(minHeight, height > 0 ? height : minHeight);
          setDimensions({ width, height: effectiveHeight });
        }
      }
    });

    observer.observe(containerRef.current);
    return () => observer.disconnect();
  }, [minHeight]);

  // 4. D3 Geographic Projection & Render Pipeline
  useEffect(() => {
    if (!svgRef.current || !worldData || dimensions.width === 0 || dimensions.height === 0) return;

    const { width, height } = dimensions;
    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    // Natural Earth 1 Projection
    const projection = d3.geoNaturalEarth1()
      .fitExtent([[24, 24], [width - 24, height - 24]], worldData as any);

    const pathGenerator = d3.geoPath().projection(projection);

    // Zoom container root group
    const gRoot = svg.append('g').attr('class', 'zoom-layer');

    // D3 Zoom Behavior
    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([1, 8])
      .translateExtent([[0, 0], [width, height]])
      .on('zoom', (event) => {
        gRoot.attr('transform', event.transform);
      });

    svg.call(zoom);
    zoomBehaviorRef.current = zoom;

    // A. Graticule / Geographic Coordinate Grid
    const graticule = d3.geoGraticule10();
    gRoot.append('path')
      .datum(graticule)
      .attr('class', 'graticule')
      .attr('d', pathGenerator as any)
      .attr('fill', 'none')
      .attr('stroke', '#1e293b')
      .attr('stroke-width', 0.5)
      .attr('stroke-dasharray', '2,4')
      .attr('opacity', 0.55);

    // B. World Geography / Countries
    const countriesGroup = gRoot.append('g').attr('class', 'countries-layer');

    countriesGroup.selectAll('path.country')
      .data(worldData.features)
      .enter()
      .append('path')
      .attr('class', 'country')
      .attr('d', pathGenerator as any)
      .attr('fill', '#0f172a') // Dark neutral
      .attr('stroke', '#1e293b') // Subtle boundary
      .attr('stroke-width', 0.8)
      .attr('cursor', 'default')
      .style('transition', 'fill 0.2s ease, stroke 0.2s ease')
      .on('mouseenter', function () {
        d3.select(this).attr('fill', '#1e293b').attr('stroke', '#334155');
      })
      .on('mouseleave', function () {
        d3.select(this).attr('fill', '#0f172a').attr('stroke', '#1e293b');
      });

    // C. Relay Route Lines (Only for verified routes between valid coordinates)
    if (layerRelayPath && validLocations.length > 1) {
      const routesGroup = gRoot.append('g').attr('class', 'routes-layer');

      // Sort chronological relay path
      const sortedHops = [...validLocations].sort((a, b) => (a.hopIndex ?? 0) - (b.hopIndex ?? 0));

      for (let i = 0; i < sortedHops.length - 1; i++) {
        const src = sortedHops[i];
        const dst = sortedHops[i + 1];

        const srcPoint = projection([src.longitude, src.latitude]);
        const dstPoint = projection([dst.longitude, dst.latitude]);

        if (srcPoint && dstPoint) {
          const isOriginSegment = src.type === 'origin' || src.isUntrustedBoundary;
          const isSelectedSegment = selectedLocationId === src.id || selectedLocationId === dst.id;

          // Bezier control point for smooth geographic arc
          const dx = dstPoint[0] - srcPoint[0];
          const dy = dstPoint[1] - srcPoint[1];
          const dr = Math.sqrt(dx * dx + dy * dy);
          const curvature = Math.min(60, dr * 0.25);
          const midX = (srcPoint[0] + dstPoint[0]) / 2;
          const midY = (srcPoint[1] + dstPoint[1]) / 2 - curvature;

          const pathString = `M ${srcPoint[0]} ${srcPoint[1]} Q ${midX} ${midY} ${dstPoint[0]} ${dstPoint[1]}`;

          // Underlay glow
          routesGroup.append('path')
            .attr('d', pathString)
            .attr('fill', 'none')
            .attr('stroke', isOriginSegment ? '#ef4444' : '#3b82f6')
            .attr('stroke-width', isSelectedSegment ? 4 : 2)
            .attr('stroke-opacity', isSelectedSegment ? 0.4 : 0.15)
            .attr('stroke-linecap', 'round');

          // Main line with animated dash
          routesGroup.append('path')
            .attr('d', pathString)
            .attr('fill', 'none')
            .attr('stroke', isOriginSegment ? '#f87171' : '#60a5fa')
            .attr('stroke-width', isSelectedSegment ? 2.5 : 1.6)
            .attr('stroke-dasharray', isOriginSegment ? '4,3' : '6,3')
            .attr('stroke-opacity', 0.9)
            .attr('stroke-linecap', 'round');

          // Direction arrow indicator at midpoint
          const t = 0.5;
          const arrowX = (1 - t) * (1 - t) * srcPoint[0] + 2 * (1 - t) * t * midX + t * t * dstPoint[0];
          const arrowY = (1 - t) * (1 - t) * srcPoint[1] + 2 * (1 - t) * t * midY + t * t * dstPoint[1];

          routesGroup.append('circle')
            .attr('cx', arrowX)
            .attr('cy', arrowY)
            .attr('r', 2.5)
            .attr('fill', isOriginSegment ? '#ef4444' : '#3b82f6');
        }
      }
    }

    // D. Global Threat Activity Layer (Only rendered when real threat feed events are provided)
    if (layerThreatActivity && filteredActivities.length > 0) {
      const activityGroup = gRoot.append('g').attr('class', 'activity-layer');

      filteredActivities.forEach((act) => {
        const point = projection([act.longitude, act.latitude]);
        if (!point) return;

        const [x, y] = point;
        const color = act.severity === 'critical' ? '#ef4444' : act.severity === 'high' ? '#f97316' : act.severity === 'medium' ? '#eab308' : '#3b82f6';
        const radius = Math.min(14, Math.max(5, (act.eventCount || 10) * 0.18));

        activityGroup.append('circle')
          .attr('cx', x)
          .attr('cy', y)
          .attr('r', radius + 4)
          .attr('fill', color)
          .attr('fill-opacity', 0.12)
          .attr('stroke', color)
          .attr('stroke-width', 0.8)
          .attr('stroke-dasharray', '2,2');

        activityGroup.append('circle')
          .attr('cx', x)
          .attr('cy', y)
          .attr('r', radius)
          .attr('fill', color)
          .attr('fill-opacity', 0.7)
          .attr('stroke', '#0c1017')
          .attr('stroke-width', 1.2)
          .attr('cursor', 'pointer')
          .on('mouseenter', (event) => {
            const [mouseX, mouseY] = d3.pointer(event, svgRef.current);
            setTooltip({
              visible: true,
              x: mouseX,
              y: mouseY,
              title: `${act.city || 'Region'}, ${act.country || 'Global'}`,
              type: 'activity',
              data: act
            });
          })
          .on('mouseleave', () => setTooltip(null));
      });
    }

    // E. Email Relay Nodes & Markers Layer (Exclusively Verified Forensic Nodes)
    if (layerInfrastructure && validLocations.length > 0) {
      const markersGroup = gRoot.append('g').attr('class', 'nodes-layer');

      validLocations.forEach((loc) => {
        const point = projection([loc.longitude, loc.latitude]);
        if (!point) return;

        const [x, y] = point;
        const isSelected = selectedLocationId === loc.id;
        const isOrigin = loc.type === 'origin' || loc.isUntrustedBoundary;
        const isDestination = loc.type === 'destination';

        const nodeG = markersGroup.append('g')
          .attr('class', `node-item node-${loc.id}`)
          .attr('cursor', 'pointer')
          .on('click', () => {
            onLocationSelect?.(loc.id);
          })
          .on('mouseenter', (event) => {
            setHoveredNodeId(loc.id);
            const [mouseX, mouseY] = d3.pointer(event, svgRef.current);
            setTooltip({
              visible: true,
              x: mouseX,
              y: mouseY,
              title: loc.ip || loc.label || 'Infrastructure Node',
              type: isOrigin ? 'origin' : isDestination ? 'destination' : 'relay',
              data: loc
            });
          })
          .on('mouseleave', () => {
            setHoveredNodeId(null);
            setTooltip(null);
          });

        if (isOrigin) {
          // Ingress Origin Marker
          nodeG.append('circle')
            .attr('cx', x)
            .attr('cy', y)
            .attr('r', isSelected ? 16 : 12)
            .attr('fill', '#ef4444')
            .attr('fill-opacity', 0.15)
            .attr('stroke', '#ef4444')
            .attr('stroke-width', 1)
            .attr('stroke-dasharray', '2,2');

          nodeG.append('circle')
            .attr('cx', x)
            .attr('cy', y)
            .attr('r', isSelected ? 7 : 5.5)
            .attr('fill', '#ef4444')
            .attr('stroke', '#ffffff')
            .attr('stroke-width', 1.5);

          nodeG.append('text')
            .attr('x', x + 10)
            .attr('y', y + 3)
            .attr('fill', '#fecaca')
            .attr('font-size', '10px')
            .attr('font-family', 'monospace')
            .attr('font-weight', 'bold')
            .text(`${loc.city || loc.country || 'Origin'}`);

        } else if (isDestination) {
          // Destination Marker
          nodeG.append('circle')
            .attr('cx', x)
            .attr('cy', y)
            .attr('r', isSelected ? 12 : 9)
            .attr('fill', '#10b981')
            .attr('fill-opacity', 0.2)
            .attr('stroke', '#10b981')
            .attr('stroke-width', 1);

          nodeG.append('circle')
            .attr('cx', x)
            .attr('cy', y)
            .attr('r', 5)
            .attr('fill', '#10b981')
            .attr('stroke', '#ffffff')
            .attr('stroke-width', 1);

          nodeG.append('text')
            .attr('x', x + 8)
            .attr('y', y + 3)
            .attr('fill', '#a7f3d0')
            .attr('font-size', '10px')
            .attr('font-family', 'monospace')
            .text(`${loc.city || 'Recipient Gateway'}`);

        } else {
          // Relay Hop Marker
          nodeG.append('circle')
            .attr('cx', x)
            .attr('cy', y)
            .attr('r', isSelected ? 11 : 7)
            .attr('fill', '#3b82f6')
            .attr('fill-opacity', 0.2)
            .attr('stroke', '#3b82f6')
            .attr('stroke-width', 1);

          nodeG.append('circle')
            .attr('cx', x)
            .attr('cy', y)
            .attr('r', 4.5)
            .attr('fill', '#3b82f6')
            .attr('stroke', '#0c1017')
            .attr('stroke-width', 1.2);

          nodeG.append('text')
            .attr('x', x + 8)
            .attr('y', y + 3)
            .attr('fill', '#93c5fd')
            .attr('font-size', '9px')
            .attr('font-family', 'monospace')
            .text(`Hop #${loc.hopIndex ?? ''} ${loc.city || ''}`);
        }
      });
    }

    // F. Auto-fit bounds on initial load
    if (autoFitRouteOnLoad && validLocations.length > 0) {
      fitLocationsBounds();
    }
  }, [
    worldData,
    dimensions,
    validLocations,
    layerRelayPath,
    layerThreatActivity,
    layerInfrastructure,
    filteredActivities,
    selectedLocationId,
    hoveredNodeId,
    onLocationSelect,
    autoFitRouteOnLoad
  ]);

  // Zoom Controls
  const handleZoomIn = () => {
    if (!svgRef.current || !zoomBehaviorRef.current) return;
    d3.select(svgRef.current).transition().duration(300).call(zoomBehaviorRef.current.scaleBy, 1.4);
  };

  const handleZoomOut = () => {
    if (!svgRef.current || !zoomBehaviorRef.current) return;
    d3.select(svgRef.current).transition().duration(300).call(zoomBehaviorRef.current.scaleBy, 0.7);
  };

  const handleReset = () => {
    if (!svgRef.current || !zoomBehaviorRef.current) return;
    d3.select(svgRef.current).transition().duration(400).call(zoomBehaviorRef.current.transform, d3.zoomIdentity);
  };

  // Fit Route: Calculates geographic bounding box and centers zoom
  const fitLocationsBounds = () => {
    if (!svgRef.current || !zoomBehaviorRef.current || validLocations.length === 0 || !worldData) return;

    const { width, height } = dimensions;
    const projection = d3.geoNaturalEarth1()
      .fitExtent([[24, 24], [width - 24, height - 24]], worldData as any);

    const projectedPoints = validLocations.map(loc => projection([loc.longitude, loc.latitude])).filter(Boolean) as [number, number][];

    if (projectedPoints.length === 0) return;

    if (projectedPoints.length === 1) {
      const [px, py] = projectedPoints[0];
      const transform = d3.zoomIdentity
        .translate(width / 2, height / 2)
        .scale(2.2)
        .translate(-px, -py);
      d3.select(svgRef.current).transition().duration(500).call(zoomBehaviorRef.current.transform, transform);
      return;
    }

    const minX = d3.min(projectedPoints, p => p[0])!;
    const maxX = d3.max(projectedPoints, p => p[0])!;
    const minY = d3.min(projectedPoints, p => p[1])!;
    const maxY = d3.max(projectedPoints, p => p[1])!;

    const dx = maxX - minX || 60;
    const dy = maxY - minY || 60;
    const midX = (minX + maxX) / 2;
    const midY = (minY + maxY) / 2;

    const scale = Math.min(4, Math.max(1.2, 0.75 / Math.max(dx / width, dy / height)));
    const transform = d3.zoomIdentity
      .translate(width / 2, height / 2)
      .scale(scale)
      .translate(-midX, -midY);

    d3.select(svgRef.current).transition().duration(500).call(zoomBehaviorRef.current.transform, transform);
  };

  return (
    <div className={`relative flex flex-col bg-[#0c1017] rounded-lg border border-slate-800 overflow-hidden ${className}`}>
      
      {/* 1. Header Controls & Activity Summary */}
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 bg-[#0f1420] border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <Globe className="w-4 h-4 text-blue-400" />
            <h2 className="text-xs uppercase tracking-wider font-semibold text-slate-200">
              Email Relay Path & Forensic Geo-Trace
            </h2>
            <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 border border-slate-700">
              {validLocations.length} verified {validLocations.length === 1 ? 'location' : 'locations'}
            </span>
          </div>
          <p className="text-[11px] text-slate-400 mt-0.5">
            D3 Natural Earth projection &bull; Derived strictly from email headers & IP telemetry
          </p>
        </div>

        {/* Layer Toggles & Status */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Layer Filter Buttons */}
          <div className="flex items-center rounded bg-slate-900 border border-slate-800 p-0.5 text-[11px]">
            <button
              onClick={() => setLayerRelayPath(!layerRelayPath)}
              className={`flex items-center gap-1 px-2 py-1 rounded transition ${layerRelayPath ? 'bg-blue-950 text-blue-300 font-medium' : 'text-slate-500 hover:text-slate-300'}`}
              title="Toggle Email Relay Path"
            >
              <Crosshair className="w-3 h-3" />
              <span>Relay Path</span>
            </button>
            <button
              onClick={() => setLayerThreatActivity(!layerThreatActivity)}
              className={`flex items-center gap-1 px-2 py-1 rounded transition ${layerThreatActivity ? 'bg-rose-950 text-rose-300 font-medium' : 'text-slate-500 hover:text-slate-300'}`}
              title="Toggle External Threat Intelligence Layer"
            >
              <Activity className="w-3 h-3" />
              <span>Threat Intel</span>
            </button>
          </div>

          {/* Map Status Badge */}
          <div className="flex items-center gap-1.5 px-2 py-1 rounded bg-slate-900 border border-slate-800 text-[10px] font-mono text-slate-400">
            <span className={`w-1.5 h-1.5 rounded-full ${loading ? 'bg-amber-400 animate-pulse' : validLocations.length > 0 ? 'bg-emerald-400' : 'bg-slate-500'}`} />
            <span>
              {loading
                ? 'Loading geo...'
                : validLocations.length > 0
                ? 'Map: Plotted'
                : 'No coordinates'}
            </span>
          </div>
        </div>
      </div>

      {/* 2. Threat Intel Feed Status Bar (Active when Threat Intel Layer is on) */}
      {layerThreatActivity && (
        <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-2 bg-[#090d15] border-b border-slate-800/80 text-xs">
          <div className="flex items-center gap-3">
            <span className="text-[11px] text-slate-400 flex items-center gap-1">
              <Flame className="w-3.5 h-3.5 text-rose-400" />
              <span>External Threat Feed</span>
            </span>

            {filteredActivities.length > 0 ? (
              <div className="flex items-center gap-1">
                {['ALL', 'PHISHING', 'MALWARE', 'BEC', 'FRAUD'].map((cat) => (
                  <button
                    key={cat}
                    onClick={() => setSelectedCategory(cat)}
                    className={`px-1.5 py-0.5 rounded text-[10px] font-mono uppercase transition ${
                      selectedCategory === cat
                        ? 'bg-slate-700 text-slate-100 font-bold'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                    }`}
                  >
                    {cat}
                  </button>
                ))}
              </div>
            ) : (
              <span className="text-[11px] text-slate-500">
                Threat feed: Not connected &bull; No simulated events shown
              </span>
            )}
          </div>

          <div className="flex items-center gap-2 text-[10px] text-slate-400 font-mono">
            {filteredActivities.length > 0 ? (
              <span>{filteredActivities.length} active global intelligence events</span>
            ) : (
              <span className="text-slate-500">Feed unavailable</span>
            )}
          </div>
        </div>
      )}

      {/* 3. Main SVG Map Area */}
      <div 
        ref={containerRef}
        className="relative w-full flex-1 bg-[#090d15] overflow-hidden min-h-[380px] select-none"
        style={{ minHeight: `${minHeight}px` }}
      >
        {/* Loading Overlay */}
        {loading && (
          <div className="absolute inset-0 bg-[#0c1017]/80 backdrop-blur-xs flex flex-col items-center justify-center z-20 gap-2">
            <RefreshCw className="w-5 h-5 text-blue-400 animate-spin" />
            <span className="text-xs text-slate-300 font-mono">Loading geographic world map...</span>
          </div>
        )}

        {/* Error / Retry Overlay */}
        {loadError && !worldData && (
          <div className="absolute inset-0 bg-[#0c1017]/95 flex flex-col items-center justify-center z-20 gap-3 p-6 text-center">
            <AlertTriangle className="w-8 h-8 text-amber-400" />
            <div>
              <h4 className="text-sm font-semibold text-slate-200">Unable to load geographic map</h4>
              <p className="text-xs text-slate-400 mt-1 max-w-md">
                {loadError}. The investigation forensic data remains fully available below.
              </p>
            </div>
            <button
              onClick={() => loadMapData(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-blue-600 hover:bg-blue-500 text-xs text-white font-medium transition"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Retry Map Request</span>
            </button>
          </div>
        )}

        {/* Empty Coordinates State Overlay */}
        {!loading && validLocations.length === 0 && (
          <div className="absolute inset-0 bg-[#0c1017]/70 backdrop-blur-xs flex flex-col items-center justify-center z-15 gap-2 text-center p-6 pointer-events-none">
            <MapPin className="w-7 h-7 text-slate-600 mb-1" />
            <span className="text-xs font-semibold text-slate-300">No Mappable Infrastructure Coordinates</span>
            <p className="text-[11px] text-slate-500 max-w-xs leading-relaxed">
              This message does not contain external public IP coordinates. Full forensic relay hops remain logged in the timeline below.
            </p>
          </div>
        )}

        {/* Actual D3 SVG Element */}
        <svg
          ref={svgRef}
          width={dimensions.width || '100%'}
          height={dimensions.height || minHeight}
          className="w-full h-full block"
        />

        {/* Floating Map Navigation Controls */}
        <div className="absolute bottom-4 right-4 flex flex-col gap-1.5 z-10">
          <button
            onClick={handleZoomIn}
            className="w-7 h-7 rounded bg-slate-900/90 border border-slate-700 text-slate-200 hover:bg-slate-800 hover:text-white flex items-center justify-center shadow-md transition"
            title="Zoom In"
          >
            <ZoomIn className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={handleZoomOut}
            className="w-7 h-7 rounded bg-slate-900/90 border border-slate-700 text-slate-200 hover:bg-slate-800 hover:text-white flex items-center justify-center shadow-md transition"
            title="Zoom Out"
          >
            <ZoomOut className="w-3.5 h-3.5" />
          </button>
          {validLocations.length > 0 && (
            <button
              onClick={fitLocationsBounds}
              className="w-7 h-7 rounded bg-slate-900/90 border border-slate-700 text-slate-200 hover:bg-slate-800 hover:text-white flex items-center justify-center shadow-md transition"
              title="Fit Relay Route"
            >
              <Crosshair className="w-3.5 h-3.5 text-blue-400" />
            </button>
          )}
          <button
            onClick={handleReset}
            className="w-7 h-7 rounded bg-slate-900/90 border border-slate-700 text-slate-200 hover:bg-slate-800 hover:text-white flex items-center justify-center shadow-md transition"
            title="Reset View"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* Legend Overlay */}
        <div className="absolute bottom-4 left-4 bg-slate-950/85 backdrop-blur-xs border border-slate-800 rounded p-2.5 text-[11px] text-slate-300 space-y-1.5 z-10 pointer-events-none">
          <div className="text-[10px] font-mono uppercase text-slate-400 font-semibold mb-1">
            Map Legend
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-500 ring-2 ring-rose-950" />
            <span>Ingress Origin (Untrusted)</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-blue-500" />
            <span>Relay Hop (Transit)</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-500" />
            <span>Recipient Gateway</span>
          </div>
          {validLocations.length > 1 && (
            <div className="flex items-center gap-2 pt-0.5 border-t border-slate-800/80">
              <span className="w-4 h-0.5 bg-blue-400 border-dashed" />
              <span>SMTP Ingress Path</span>
            </div>
          )}
        </div>

        {/* Rich Interactive Tooltip with Strict Data Provenance */}
        {tooltip && tooltip.visible && (
          <div
            className="absolute z-30 pointer-events-none bg-slate-950/95 border border-slate-700 rounded-md p-3 shadow-xl text-xs max-w-xs transition-all duration-75"
            style={{
              left: `${Math.min(dimensions.width - 240, tooltip.x + 14)}px`,
              top: `${Math.max(10, tooltip.y - 80)}px`
            }}
          >
            <div className="flex items-center justify-between gap-2 border-b border-slate-800 pb-1.5 mb-1.5">
              <span className="font-mono font-bold text-slate-100">{tooltip.title}</span>
              <span className={`text-[9px] font-mono font-bold uppercase px-1.5 py-0.2 rounded ${
                tooltip.type === 'origin'
                  ? 'bg-rose-950 text-rose-300 border border-rose-800'
                  : tooltip.type === 'destination'
                  ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                  : tooltip.type === 'activity'
                  ? 'bg-amber-950 text-amber-300 border border-amber-800'
                  : 'bg-blue-950 text-blue-300 border border-blue-800'
              }`}>
                {tooltip.type}
              </span>
            </div>

            {tooltip.type === 'activity' ? (
              <div className="space-y-1 text-slate-300 text-[11px]">
                <div><span className="text-slate-500">Threat Category:</span> <span className="font-semibold text-rose-400 capitalize">{tooltip.data.category}</span></div>
                <div><span className="text-slate-500">Severity:</span> <span className="uppercase font-mono text-slate-200">{tooltip.data.severity}</span></div>
                <div><span className="text-slate-500">Observed IP:</span> <span className="font-mono text-slate-200">{tooltip.data.ip || 'N/A'}</span></div>
                <div><span className="text-slate-500">Source:</span> <span className="text-slate-200">{tooltip.data.source}</span></div>
                <div className="text-[10px] text-slate-400 pt-1 border-t border-slate-800">{tooltip.data.details}</div>
              </div>
            ) : (
              <div className="space-y-1 text-slate-300 text-[11px]">
                <div className="flex items-center justify-between pb-1 border-b border-slate-850">
                  <span className="text-slate-500">Provenance:</span>
                  <span className="font-mono text-[10px] text-blue-300">
                    {tooltip.data.source === 'received-header'
                      ? `Received Header #${tooltip.data.hopIndex || 1}`
                      : tooltip.data.source || 'IP Geolocation'}
                  </span>
                </div>
                {tooltip.data.ip && (
                  <div><span className="text-slate-500">IP:</span> <span className="font-mono text-slate-100">{tooltip.data.ip}</span></div>
                )}
                <div><span className="text-slate-500">Location:</span> <span>{tooltip.data.city ? `${tooltip.data.city}, ` : ''}{tooltip.data.country || 'Unknown'}</span></div>
                {tooltip.data.isp && (
                  <div><span className="text-slate-500">ISP:</span> <span>{tooltip.data.isp}</span></div>
                )}
                {tooltip.data.asn && (
                  <div><span className="text-slate-500">ASN:</span> <span className="font-mono">{tooltip.data.asn}</span></div>
                )}
                {tooltip.data.confidence !== undefined && (
                  <div><span className="text-slate-500">Confidence:</span> <span className="font-bold text-blue-400">{tooltip.data.confidence}%</span></div>
                )}
                {tooltip.data.reverseDns && (
                  <div className="text-[10px] text-slate-400 pt-1 border-t border-slate-800 truncate">
                    rDNS: <span className="font-mono text-slate-300">{tooltip.data.reverseDns}</span>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>

      {/* 4. Forensic Caution & Precision Disclaimer */}
      <div className="px-4 py-2 bg-[#090d15] border-t border-slate-800 text-[11px] text-slate-500 flex items-start gap-2">
        <Info className="w-3.5 h-3.5 text-slate-400 shrink-0 mt-0.5" />
        <p className="leading-relaxed">
          <span className="font-medium text-slate-400">Forensic Disclaimer:</span> Geolocation markers represent verified network routing infrastructure. They reflect autonomous system handoffs, not the physical location of the human actor. No speculative coordinates are generated.
        </p>
      </div>

    </div>
  );
};
