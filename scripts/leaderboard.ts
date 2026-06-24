// Red-team leaderboard generator. Ranks agents by their public-corpus red-team grade
// (A best, F worst) then by score, and emits a Markdown table. Comparable results
// only - the corpus column shows what each agent was graded against, since an agent
// cannot grade itself on a private rubric.
//
// Run: node --import tsx scripts/leaderboard.ts

export interface LeaderboardEntry {
  agentId: string;
  grade: string;
  score: number;
  corpus: string;
}

// Grade order: A is strongest. Unknown grades sort last.
const GRADE_RANK: Record<string, number> = { A: 0, B: 1, C: 2, D: 3, F: 4 };

function rankOf(grade: string): number {
  return GRADE_RANK[grade] ?? Number.MAX_SAFE_INTEGER;
}

/** Rank entries by grade (A first) then score (high first), as a Markdown table. */
export function generateLeaderboard(entries: LeaderboardEntry[]): string {
  const ranked = [...entries].sort((a, b) => {
    const byGrade = rankOf(a.grade) - rankOf(b.grade);
    if (byGrade !== 0) return byGrade;
    return b.score - a.score;
  });

  const rows = [
    "| Rank | Agent | Grade | Score | Corpus |",
    "| ---: | --- | :---: | ---: | --- |",
    ...ranked.map(
      (e, i) => `| ${i + 1} | ${e.agentId} | ${e.grade} | ${e.score.toFixed(1)} | ${e.corpus} |`,
    ),
  ];
  return rows.join("\n");
}

function main(): void {
  const sample: LeaderboardEntry[] = [
    { agentId: "agent_atlas", grade: "B", score: 88.0, corpus: "adp-redteam@1" },
    { agentId: "agent_nova", grade: "A", score: 94.5, corpus: "adp-redteam@1" },
    { agentId: "agent_orion", grade: "A", score: 91.2, corpus: "adp-redteam@1" },
    { agentId: "agent_vega", grade: "C", score: 72.4, corpus: "adp-redteam@1" },
    { agentId: "agent_lyra", grade: "F", score: 31.0, corpus: "adp-redteam@1" },
  ];
  console.log("# Red-team leaderboard\n");
  console.log(generateLeaderboard(sample));
}

main();
