export function calculateTrendScore(repo) {
  const totalStars = repo.stargazers_count || 0;
  const totalForks = repo.forks_count || 0;

  const starsScore = Math.log1p(totalStars);
  const forksScore = Math.log1p(totalForks);

  // Commit recency score using exponential decay
  const lastPushedAt = repo.pushed_at;
  let recencyScore = 0;

  if (lastPushedAt) {
    const daysSinceLastCommit =
      (Date.now() - new Date(lastPushedAt).getTime()) /
      (1000 * 60 * 60 * 24);

    const decayFactor = 30; // days
    recencyScore = Math.exp(-daysSinceLastCommit / decayFactor);
  }

  // Final weighted trend score
  const trendScore =
    (0.4 * starsScore) +
    (0.3 * forksScore) +
    (0.3 * recencyScore);

  return Number(trendScore.toFixed(4));
}

