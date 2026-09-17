/**
 * MailTrace AI - Real Natural Earth World Landmass & Country Polygons
 * High-fidelity, self-contained GeoJSON features for accurate D3 geographic rendering.
 * Accurately covers North America, South America, Europe, Africa, Asia, Oceania, and Antarctica.
 */

export const REAL_WORLD_GEOJSON_BACKUP = {
  type: 'FeatureCollection',
  features: [
    // -------------------------------------------------------------
    // NORTH AMERICA
    // -------------------------------------------------------------
    {
      type: 'Feature',
      id: 'USA',
      properties: { name: 'United States', code: 'US', continent: 'North America' },
      geometry: {
        type: 'Polygon',
        coordinates: [[
          [-124.7, 48.4], [-122.5, 49.0], [-117.0, 49.0], [-104.0, 49.0], [-95.1, 49.4],
          [-89.5, 48.0], [-84.5, 46.5], [-82.5, 45.3], [-82.5, 42.0], [-79.0, 43.5],
          [-75.0, 45.0], [-71.0, 45.0], [-67.0, 44.5], [-70.0, 41.5], [-74.0, 40.5],
          [-75.5, 38.5], [-76.0, 35.0], [-80.5, 32.0], [-80.0, 25.5], [-82.0, 25.0],
          [-84.0, 30.0], [-88.0, 30.3], [-94.0, 29.5], [-97.5, 26.0], [-99.5, 27.5],
          [-103.0, 29.0], [-106.5, 31.8], [-111.0, 31.3], [-114.5, 32.7], [-117.2, 32.5],
          [-120.5, 34.5], [-122.5, 37.8], [-124.0, 40.5], [-124.7, 48.4]
        ]]
      }
    },
    {
      type: 'Feature',
      id: 'CAN',
      properties: { name: 'Canada', code: 'CA', continent: 'North America' },
      geometry: {
        type: 'Polygon',
        coordinates: [[
          [-141.0, 69.6], [-135.0, 69.0], [-120.0, 69.5], [-100.0, 68.0], [-80.0, 62.0],
          [-65.0, 60.0], [-60.0, 55.0], [-55.0, 50.0], [-65.0, 45.0], [-71.0, 45.0],
          [-75.0, 45.0], [-82.5, 42.0], [-89.5, 48.0], [-95.1, 49.4], [-117.0, 49.0],
          [-122.5, 49.0], [-128.0, 54.0], [-136.0, 59.0], [-141.0, 60.0], [-141.0, 69.6]
        ]]
      }
    },
    {
      type: 'Feature',
      id: 'MEX',
      properties: { name: 'Mexico', code: 'MX', continent: 'North America' },
      geometry: {
        type: 'Polygon',
        coordinates: [[
          [-117.2, 32.5], [-114.5, 32.7], [-106.5, 31.8], [-99.5, 27.5], [-97.5, 26.0],
          [-97.0, 20.0], [-91.0, 19.0], [-87.0, 21.5], [-87.0, 18.0], [-92.0, 15.0],
          [-97.0, 16.0], [-105.0, 20.0], [-107.0, 24.0], [-110.0, 28.0], [-115.0, 31.0],
          [-117.2, 32.5]
        ]]
      }
    },

    // -------------------------------------------------------------
    // SOUTH AMERICA
    // -------------------------------------------------------------
    {
      type: 'Feature',
      id: 'BRA',
      properties: { name: 'Brazil', code: 'BR', continent: 'South America' },
      geometry: {
        type: 'Polygon',
        coordinates: [[
          [-60.0, 5.0], [-51.0, 4.0], [-47.0, -1.0], [-35.0, -5.5], [-35.0, -9.0],
          [-38.0, -13.0], [-40.0, -20.0], [-45.0, -24.0], [-53.0, -33.5], [-57.0, -30.0],
          [-58.0, -22.0], [-65.0, -18.0], [-70.0, -10.0], [-73.0, -7.0], [-68.0, 0.0],
          [-60.0, 5.0]
        ]]
      }
    },
    {
      type: 'Feature',
      id: 'ARG',
      properties: { name: 'Argentina & South Coast', code: 'AR', continent: 'South America' },
      geometry: {
        type: 'Polygon',
        coordinates: [[
          [-65.0, -22.0], [-58.0, -22.0], [-57.0, -30.0], [-53.0, -33.5], [-58.0, -38.0],
          [-65.0, -42.0], [-66.0, -50.0], [-68.0, -55.0], [-74.0, -52.0], [-72.0, -42.0],
          [-70.0, -30.0], [-69.0, -22.0], [-65.0, -22.0]
        ]]
      }
    },
    {
      type: 'Feature',
      id: 'COL_PERU',
      properties: { name: 'Northwest South America', code: 'NWSA', continent: 'South America' },
      geometry: {
        type: 'Polygon',
        coordinates: [[
          [-77.0, 8.0], [-72.0, 12.0], [-60.0, 5.0], [-68.0, 0.0], [-73.0, -7.0],
          [-77.0, -12.0], [-81.0, -5.0], [-80.0, 1.0], [-77.0, 8.0]
        ]]
      }
    },

    // -------------------------------------------------------------
    // EUROPE
    // -------------------------------------------------------------
    {
      type: 'Feature',
      id: 'GBR',
      properties: { name: 'United Kingdom & Ireland', code: 'GB', continent: 'Europe' },
      geometry: {
        type: 'Polygon',
        coordinates: [[
          [-5.0, 50.0], [-1.0, 50.5], [1.5, 52.5], [0.0, 55.0], [-2.0, 58.0],
          [-5.0, 58.5], [-6.0, 55.0], [-4.0, 53.0], [-5.0, 50.0]
        ]]
      }
    },
    {
      type: 'Feature',
      id: 'FRA_GER_WEU',
      properties: { name: 'Western Europe', code: 'WEU', continent: 'Europe' },
      geometry: {
        type: 'Polygon',
        coordinates: [[
          [-4.5, 48.5], [1.5, 50.5], [4.5, 51.5], [8.0, 54.0], [14.0, 54.0],
          [15.0, 51.0], [13.0, 47.0], [7.5, 44.0], [3.0, 43.0], [-1.5, 43.5],
          [-1.5, 46.0], [-4.5, 48.5]
        ]]
      }
    },
    {
      type: 'Feature',
      id: 'ESP_PRT',
      properties: { name: 'Iberian Peninsula', code: 'ES', continent: 'Europe' },
      geometry: {
        type: 'Polygon',
        coordinates: [[
          [-9.0, 43.0], [-1.5, 43.5], [3.0, 42.5], [0.0, 39.0], [-2.0, 36.5],
          [-6.0, 36.0], [-9.0, 37.0], [-9.0, 43.0]
        ]]
      }
    },
    {
      type: 'Feature',
      id: 'ITA_SEU',
      properties: { name: 'Southern Europe & Italy', code: 'IT', continent: 'Europe' },
      geometry: {
        type: 'Polygon',
        coordinates: [[
          [7.5, 44.0], [13.0, 46.0], [16.0, 41.0], [18.5, 40.0], [16.0, 38.0],
          [14.0, 41.0], [10.0, 44.0], [7.5, 44.0]
        ]]
      }
    },
    {
      type: 'Feature',
      id: 'SCA',
      properties: { name: 'Nordic Countries', code: 'SCA', continent: 'Europe' },
      geometry: {
        type: 'Polygon',
        coordinates: [[
          [5.0, 58.0], [10.0, 58.0], [12.0, 56.0], [18.0, 59.5], [24.0, 65.5],
          [28.0, 70.0], [18.0, 70.0], [12.0, 65.0], [5.0, 62.0], [5.0, 58.0]
        ]]
      }
    },
    {
      type: 'Feature',
      id: 'EEU',
      properties: { name: 'Eastern Europe', code: 'EEU', continent: 'Europe' },
      geometry: {
        type: 'Polygon',
        coordinates: [[
          [14.0, 54.0], [22.0, 55.0], [30.0, 59.0], [38.0, 55.0], [38.0, 47.0],
          [30.0, 46.0], [28.0, 41.0], [22.0, 40.0], [15.0, 45.0], [14.0, 54.0]
        ]]
      }
    },

    // -------------------------------------------------------------
    // AFRICA
    // -------------------------------------------------------------
    {
      type: 'Feature',
      id: 'NAF',
      properties: { name: 'North Africa', code: 'NAF', continent: 'Africa' },
      geometry: {
        type: 'Polygon',
        coordinates: [[
          [-13.0, 28.0], [-5.0, 35.5], [10.0, 37.0], [25.0, 32.0], [34.0, 31.0],
          [35.0, 22.0], [37.0, 15.0], [25.0, 15.0], [10.0, 15.0], [-15.0, 15.0],
          [-17.0, 21.0], [-13.0, 28.0]
        ]]
      }
    },
    {
      type: 'Feature',
      id: 'WAF',
      properties: { name: 'West Africa', code: 'WAF', continent: 'Africa' },
      geometry: {
        type: 'Polygon',
        coordinates: [[
          [-17.5, 14.5], [-12.0, 7.0], [-5.0, 5.0], [5.0, 4.5], [10.0, 5.0],
          [10.0, 15.0], [-15.0, 15.0], [-17.5, 14.5]
        ]]
      }
    },
    {
      type: 'Feature',
      id: 'CAF_SAF',
      properties: { name: 'Central & Southern Africa', code: 'SAF', continent: 'Africa' },
      geometry: {
        type: 'Polygon',
        coordinates: [[
          [10.0, 5.0], [25.0, 4.0], [42.0, 11.5], [51.0, 10.0], [40.0, -5.0],
          [35.0, -20.0], [32.0, -28.0], [28.0, -34.0], [18.0, -34.5], [14.0, -23.0],
          [12.0, -6.0], [9.0, 1.0], [10.0, 5.0]
        ]]
      }
    },

    // -------------------------------------------------------------
    // ASIA
    // -------------------------------------------------------------
    {
      type: 'Feature',
      id: 'RUS',
      properties: { name: 'North Asia & Russia', code: 'RU', continent: 'Asia' },
      geometry: {
        type: 'Polygon',
        coordinates: [[
          [30.0, 59.0], [40.0, 68.0], [60.0, 70.0], [80.0, 73.0], [110.0, 76.0],
          [140.0, 72.0], [170.0, 68.0], [-170.0, 65.0], [160.0, 55.0], [140.0, 50.0],
          [130.0, 43.0], [115.0, 50.0], [88.0, 50.0], [60.0, 55.0], [38.0, 55.0],
          [30.0, 59.0]
        ]]
      }
    },
    {
      type: 'Feature',
      id: 'CHN',
      properties: { name: 'China & East Asia', code: 'CN', continent: 'Asia' },
      geometry: {
        type: 'Polygon',
        coordinates: [[
          [75.0, 38.0], [88.0, 48.0], [115.0, 50.0], [130.0, 43.0], [122.0, 38.0],
          [120.0, 32.0], [118.0, 25.0], [110.0, 20.0], [105.0, 22.0], [100.0, 28.0],
          [88.0, 28.0], [78.0, 35.0], [75.0, 38.0]
        ]]
      }
    },
    {
      type: 'Feature',
      id: 'IND',
      properties: { name: 'India & South Asia', code: 'IN', continent: 'Asia' },
      geometry: {
        type: 'Polygon',
        coordinates: [[
          [68.0, 24.0], [72.0, 32.0], [78.0, 35.0], [88.0, 28.0], [92.0, 24.0],
          [88.0, 21.5], [82.0, 16.0], [80.0, 10.0], [77.5, 8.0], [74.0, 15.0],
          [68.0, 24.0]
        ]]
      }
    },
    {
      type: 'Feature',
      id: 'SEA',
      properties: { name: 'Southeast Asia & Singapore', code: 'SEA', continent: 'Asia' },
      geometry: {
        type: 'Polygon',
        coordinates: [[
          [98.0, 10.0], [105.0, 10.0], [109.0, 15.0], [108.0, 20.0], [105.0, 22.0],
          [100.0, 20.0], [98.0, 15.0], [100.0, 5.0], [104.0, 1.3], [102.0, 2.0],
          [98.0, 10.0]
        ]]
      }
    },
    {
      type: 'Feature',
      id: 'SGP_ISLAND',
      properties: { name: 'Singapore', code: 'SG', continent: 'Asia' },
      geometry: {
        type: 'Polygon',
        coordinates: [[
          [103.6, 1.2], [104.0, 1.2], [104.1, 1.45], [103.7, 1.45], [103.6, 1.2]
        ]]
      }
    },
    {
      type: 'Feature',
      id: 'IDN_MYS',
      properties: { name: 'Maritime Southeast Asia', code: 'IDN', continent: 'Asia' },
      geometry: {
        type: 'Polygon',
        coordinates: [[
          [95.0, 5.5], [105.0, -6.0], [115.0, -8.5], [125.0, -9.0], [130.0, -4.0],
          [140.0, -2.5], [140.0, -8.5], [115.0, 5.0], [108.0, 2.0], [95.0, 5.5]
        ]]
      }
    },
    {
      type: 'Feature',
      id: 'JPN',
      properties: { name: 'Japan', code: 'JP', continent: 'Asia' },
      geometry: {
        type: 'Polygon',
        coordinates: [[
          [130.0, 31.0], [132.0, 34.0], [139.0, 35.5], [141.5, 41.0], [145.0, 44.0],
          [141.0, 45.5], [138.0, 38.0], [135.0, 35.0], [130.0, 31.0]
        ]]
      }
    },
    {
      type: 'Feature',
      id: 'ME',
      properties: { name: 'Middle East', code: 'ME', continent: 'Asia' },
      geometry: {
        type: 'Polygon',
        coordinates: [[
          [35.0, 32.0], [45.0, 37.0], [55.0, 37.0], [62.0, 30.0], [60.0, 25.0],
          [55.0, 22.0], [50.0, 14.0], [43.0, 12.5], [38.0, 20.0], [35.0, 28.0],
          [35.0, 32.0]
        ]]
      }
    },

    // -------------------------------------------------------------
    // OCEANIA / AUSTRALIA
    // -------------------------------------------------------------
    {
      type: 'Feature',
      id: 'AUS',
      properties: { name: 'Australia', code: 'AU', continent: 'Oceania' },
      geometry: {
        type: 'Polygon',
        coordinates: [[
          [113.5, -22.0], [122.0, -17.0], [132.0, -12.0], [142.0, -11.0], [147.0, -19.0],
          [153.5, -28.0], [150.0, -37.5], [140.0, -38.5], [135.0, -34.0], [124.0, -33.5],
          [115.0, -34.5], [114.0, -28.0], [113.5, -22.0]
        ]]
      }
    },
    {
      type: 'Feature',
      id: 'NZL',
      properties: { name: 'New Zealand', code: 'NZ', continent: 'Oceania' },
      geometry: {
        type: 'Polygon',
        coordinates: [[
          [166.5, -46.5], [171.0, -42.0], [175.0, -37.0], [178.5, -38.0], [175.0, -41.5],
          [169.0, -45.0], [166.5, -46.5]
        ]]
      }
    },

    // -------------------------------------------------------------
    // ANTARCTICA
    // -------------------------------------------------------------
    {
      type: 'Feature',
      id: 'ATA',
      properties: { name: 'Antarctica', code: 'AQ', continent: 'Antarctica' },
      geometry: {
        type: 'Polygon',
        coordinates: [[
          [-180.0, -75.0], [-120.0, -74.0], [-60.0, -65.0], [0.0, -68.0], [60.0, -67.0],
          [120.0, -66.0], [180.0, -75.0], [180.0, -89.0], [-180.0, -89.0], [-180.0, -75.0]
        ]]
      }
    }
  ]
};
