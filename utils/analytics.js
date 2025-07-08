const { BetaAnalyticsDataClient } = require('@google-analytics/data');

const client = new BetaAnalyticsDataClient({
  keyFilename: './ga-key.json', // path to your downloaded JSON key
});

async function getGAStats() {
  const [response] = await client.runReport({
    property: 'properties/495906903', // e.g., properties/1234567890
    dateRanges: [{ startDate: '7daysAgo', endDate: 'today' }],
    dimensions: [{ name: 'date' }],
    metrics: [
      { name: 'sessions' },
      { name: 'totalUsers' }
    ],
  });

  return response.rows.map(row => ({
    date: row.dimensionValues[0].value,
    sessions: Number(row.metricValues[0].value),
    users: Number(row.metricValues[1].value),
  }));
}

module.exports = getGAStats;
