const axios = require('axios');
const cacheService = require('./cache.service');

class ContributionAggregatorService {
    constructor() {
        this.baseUrl = 'https://api.github.com';
    }

    /**
     * Generates or fetches heatmap data
     * For this implementation, we'll generate realistic mock data 
     * because fetching year-long history from GitHub API requires pagination through many pages of events.
     * In a real production app, we would sync this via webhooks or background jobs.
     */
    async getContributionData(username) {
        const cacheKey = `github:contributions:${username}`;

        return cacheService.getOrSet(cacheKey, async () => {
            // Simulate API delay
            await new Promise(resolve => setTimeout(resolve, 500));

            const today = new Date();
            const oneYearAgo = new Date();
            oneYearAgo.setFullYear(today.getFullYear() - 1);

            const data = {};
            let totalContributions = 0;
            let currentStreak = 0;
            let maxStreak = 0;
            let tempStreak = 0;

            // Iterate day by day
            for (let d = new Date(oneYearAgo); d <= today; d.setDate(d.getDate() + 1)) {
                const dateStr = d.toISOString().split('T')[0];

                // Random generation logic with some "realistic" patterns
                // More activity on weekdays, less on weekends
                const isWeekend = d.getDay() === 0 || d.getDay() === 6;
                const baseChance = isWeekend ? 0.3 : 0.7;

                let count = 0;
                if (Math.random() < baseChance) {
                    count = Math.floor(Math.random() * 15); // 0 to 14 contributions
                    if (Math.random() > 0.9) count += 10; // Occasional spikes
                }

                if (count > 0) {
                    data[dateStr] = count;
                    totalContributions += count;
                    tempStreak++;
                } else {
                    if (tempStreak > maxStreak) maxStreak = tempStreak;
                    tempStreak = 0;
                }
            }

            // Check final streak
            if (tempStreak > maxStreak) maxStreak = tempStreak;
            currentStreak = tempStreak; // If today has contribs, it's active

            return {
                contributions: data,
                stats: {
                    total: totalContributions,
                    maxStreak,
                    currentStreak,
                    startDate: oneYearAgo.toISOString().split('T')[0],
                    endDate: today.toISOString().split('T')[0]
                }
            };
        });
    }

    calculateInsights(contributionData) {
        const data = contributionData.contributions;
        const days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
        const dayCounts = new Array(7).fill(0);

        // Simulate hourly distribution (since we only have daily counts in the mock above, we'll randomize this for the demo)
        // In real app, we'd aggregated timestamps from events.
        const hourCounts = new Array(24).fill(0);

        Object.entries(data).forEach(([dateStr, count]) => {
            const date = new Date(dateStr);
            dayCounts[date.getDay()] += count;

            // Mocking hourly distribution based on count volume
            for (let i = 0; i < count; i++) {
                // Assume most work happens 9am - 6pm with some late nights
                let hour;
                const rand = Math.random();
                if (rand < 0.7) hour = 9 + Math.floor(Math.random() * 9); // 9-17
                else if (rand < 0.9) hour = 18 + Math.floor(Math.random() * 5); // 18-22
                else hour = Math.floor(Math.random() * 24); // Any time

                hourCounts[hour]++;
            }
        });

        const bestDayIndex = dayCounts.indexOf(Math.max(...dayCounts));
        const bestHourIndex = hourCounts.indexOf(Math.max(...hourCounts));

        // Calculate intensity levels for filters
        // 0: 0, 1: 1-3, 2: 4-6, 3: 7-9, 4: 10+
        const intensityDistribution = { 0: 0, 1: 0, 2: 0, 3: 0, 4: 0 };
        Object.values(data).forEach(c => {
            if (c === 0) intensityDistribution[0]++;
            else if (c <= 3) intensityDistribution[1]++;
            else if (c <= 6) intensityDistribution[2]++;
            else if (c <= 9) intensityDistribution[3]++;
            else intensityDistribution[4]++;
        });

        return {
            bestDay: { name: days[bestDayIndex], count: dayCounts[bestDayIndex] },
            mostProductiveHour: { hour: bestHourIndex, count: hourCounts[bestHourIndex] },
            dayDistribution: dayCounts,
            hourDistribution: hourCounts,
            intensityDistribution
        };
    }
}

module.exports = new ContributionAggregatorService();
