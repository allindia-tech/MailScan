/**
 * MailTrace AI - Dedicated World Map Data Loader & Cache Engine
 * Manages loading, validating, caching, and projecting world GeoJSON / TopoJSON features.
 * Guarantees zero runtime crashes, instant offline fallback, and high-fidelity Natural Earth geography.
 */

import * as topojson from 'topojson-client';
import { REAL_WORLD_GEOJSON_BACKUP } from './worldGeoData.js';

export interface WorldMapFeatureCollection {
  type: 'FeatureCollection';
  features: Array<{
    type: 'Feature';
    id?: string | number;
    properties: {
      name?: string;
      [key: string]: any;
    };
    geometry: {
      type: 'Polygon' | 'MultiPolygon';
      coordinates: any;
    };
  }>;
}

export interface MapLoaderResult {
  features: WorldMapFeatureCollection;
  isCached: boolean;
  source: 'network' | 'cache' | 'bundled_fallback';
  countryCount: number;
}

// In-Memory Cache
let cachedWorldGeoJSON: WorldMapFeatureCollection | null = null;
let activeFetchPromise: Promise<MapLoaderResult> | null = null;

export class WorldMapDataLoader {
  private static REMOTE_WORLD_ATLAS_URLS = [
    'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json',
    'https://unpkg.com/world-atlas@2/countries-110m.json'
  ];

  /**
   * Validate that a GeoJSON object contains valid FeatureCollection geometries
   */
  public static validateWorldMap(data: any): boolean {
    if (!data || typeof data !== 'object') return false;
    if (data.type !== 'FeatureCollection') return false;
    if (!Array.isArray(data.features) || data.features.length === 0) return false;

    // Check first few features for valid polygon geometries
    const sample = data.features.slice(0, 5);
    for (const f of sample) {
      if (!f.geometry || !['Polygon', 'MultiPolygon'].includes(f.geometry.type)) {
        return false;
      }
      if (!Array.isArray(f.geometry.coordinates) || f.geometry.coordinates.length === 0) {
        return false;
      }
    }
    return true;
  }

  /**
   * Cache validated world map features in memory
   */
  public static cacheWorldMap(geoJson: WorldMapFeatureCollection): void {
    if (this.validateWorldMap(geoJson)) {
      cachedWorldGeoJSON = geoJson;
    }
  }

  /**
   * Get cached features if available
   */
  public static getCachedFeatures(): WorldMapFeatureCollection | null {
    return cachedWorldGeoJSON;
  }

  /**
   * Main loader: Attempts cache -> remote TopoJSON -> bundled offline fallback
   */
  public static async loadWorldMap(forceReload = false): Promise<MapLoaderResult> {
    if (!forceReload && cachedWorldGeoJSON) {
      return {
        features: cachedWorldGeoJSON,
        isCached: true,
        source: 'cache',
        countryCount: cachedWorldGeoJSON.features.length
      };
    }

    if (activeFetchPromise && !forceReload) {
      return activeFetchPromise;
    }

    activeFetchPromise = (async () => {
      // 1. Try remote TopoJSON world atlas
      for (const url of this.REMOTE_WORLD_ATLAS_URLS) {
        try {
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 3500);

          const response = await fetch(url, { signal: controller.signal });
          clearTimeout(timeoutId);

          if (response.ok) {
            const topology = await response.json();
            if (topology && topology.objects && (topology.objects.countries || topology.objects.land)) {
              const objectKey = topology.objects.countries ? 'countries' : 'land';
              const converted = topojson.feature(topology, topology.objects[objectKey]) as any;

              if (this.validateWorldMap(converted)) {
                this.cacheWorldMap(converted);
                return {
                  features: converted,
                  isCached: false,
                  source: 'network' as const,
                  countryCount: converted.features.length
                };
              }
            }
          }
        } catch {
          // Gracefully continue to next URL or fallback
        }
      }

      // 2. Fallback to bundled high-fidelity Natural Earth world dataset
      const bundled = REAL_WORLD_GEOJSON_BACKUP as unknown as WorldMapFeatureCollection;
      this.cacheWorldMap(bundled);

      return {
        features: bundled,
        isCached: false,
        source: 'bundled_fallback' as const,
        countryCount: bundled.features.length
      };
    })();

    try {
      const res = await activeFetchPromise;
      return res;
    } finally {
      activeFetchPromise = null;
    }
  }

  /**
   * Synchronously return cached or bundled features for instant render
   */
  public static returnGeoFeatures(): WorldMapFeatureCollection {
    if (cachedWorldGeoJSON) return cachedWorldGeoJSON;
    return REAL_WORLD_GEOJSON_BACKUP as unknown as WorldMapFeatureCollection;
  }
}
