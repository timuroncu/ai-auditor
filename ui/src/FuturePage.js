import React, { useState } from 'react';
import {
  Shield, Clock, History, GitCompare, BarChart3, Vote,
  Brain, Lightbulb, GitBranch, Cpu, AlertTriangle, Workflow,
  ChevronDown, ChevronUp, CheckCircle, XCircle, AlertCircle,
  TrendingUp, Users, Bot, Zap, FileCode, Calendar, Target,
  Gauge, Code, Settings, Play, ArrowRight, Star, Lock,
  Eye, Layers, Filter, RefreshCw
} from 'lucide-react';
import './FuturePage.css';

// Mock Data
const mockHistoryData = [
  {
    id: 1,
    repo: 'itublockchain/mamutiki-front',
    date: '2025-01-03 14:32',
    confirmed: 2,
    lowProb: 0,
    safe: 0,
    status: 'critical'
  },
  {
    id: 2,
    repo: 'facebook/react',
    date: '2025-01-03 12:15',
    confirmed: 0,
    lowProb: 3,
    safe: 12,
    status: 'safe'
  },
  {
    id: 3,
    repo: 'vercel/next.js',
    date: '2025-01-02 18:45',
    confirmed: 1,
    lowProb: 2,
    safe: 8,
    status: 'warning'
  },
  {
    id: 4,
    repo: 'microsoft/vscode',
    date: '2025-01-02 09:20',
    confirmed: 0,
    lowProb: 1,
    safe: 25,
    status: 'safe'
  },
  {
    id: 5,
    repo: 'django/django',
    date: '2025-01-01 16:00',
    confirmed: 3,
    lowProb: 4,
    safe: 18,
    status: 'critical'
  }
];

const mockAgentComparison = {
  vulnerability: 'SQL Injection in user_controller.py:45',
  agents: {
    openai: {
      verdict: true,
      confidence: 0.92,
      riskLevel: 'HIGH',
      reasoning: 'User input is directly concatenated into SQL query without parameterization. The execute() call on line 47 passes unsanitized user_id from request.args directly into the query string.',
      recommendation: 'Use parameterized queries with placeholders. Replace string formatting with cursor.execute(query, (user_id,))'
    },
    claude: {
      verdict: true,
      confidence: 0.88,
      riskLevel: 'HIGH',
      reasoning: 'Classic SQL injection pattern detected. The user_id parameter flows from request.args["id"] through string concatenation into the SQL query. No input validation or sanitization is present.',
      recommendation: 'Implement prepared statements using SQLAlchemy ORM or psycopg2 parameterized queries. Add input validation for user_id.'
    },
    localML: {
      verdict: true,
      confidence: 0.76,
      riskLevel: 'MEDIUM',
      reasoning: 'Pattern matching detected SQL query construction with variable interpolation. Similarity score 0.89 with known vulnerable patterns in training set.',
      recommendation: 'Review database access patterns. Consider ORM usage.'
    }
  }
};

const mockMetrics = {
  overall: {
    precision: 0.847,
    recall: 0.912,
    f1Score: 0.878,
    accuracy: 0.891
  },
  byAgent: {
    openai: { precision: 0.89, recall: 0.94, f1: 0.91, scanned: 1250 },
    claude: { precision: 0.86, recall: 0.91, f1: 0.88, scanned: 1250 },
    localML: { precision: 0.79, recall: 0.87, f1: 0.83, scanned: 1250 }
  },
  confusionMatrix: {
    tp: 156,
    fp: 28,
    tn: 892,
    fn: 15
  },
  vulnTypes: [
    { type: 'SQL Injection', count: 45, detected: 43 },
    { type: 'XSS', count: 38, detected: 35 },
    { type: 'Path Traversal', count: 22, detected: 20 },
    { type: 'Command Injection', count: 18, detected: 17 },
    { type: 'SSRF', count: 12, detected: 11 }
  ]
};

const mockModelInfo = {
  name: 'CodeBERT-Phase2-Final',
  version: '2.1.0',
  trainingSize: '125,000 samples',
  lastTrained: '2025-01-01',
  accuracy: '87.3%',
  parameters: '125M',
  languages: ['Python', 'JavaScript', 'Java', 'Go', 'C/C++']
};

// Feature Card Component
const FeatureSection = ({ icon: Icon, title, badge, children, isOpen, onToggle }) => (
  <div className={`feature-section ${isOpen ? 'open' : ''}`}>
    <div className="feature-header" onClick={onToggle}>
      <div className="feature-title">
        <Icon className="feature-icon" size={24} />
        <h3>{title}</h3>
        {badge && <span className="feature-badge">{badge}</span>}
      </div>
      {isOpen ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
    </div>
    {isOpen && <div className="feature-content">{children}</div>}
  </div>
);

// 1. Analysis History Component
const AnalysisHistory = () => {
  const [selectedItem, setSelectedItem] = useState(null);

  return (
    <div className="history-container">
      <div className="history-list">
        {mockHistoryData.map((item) => (
          <div
            key={item.id}
            className={`history-item ${selectedItem?.id === item.id ? 'selected' : ''}`}
            onClick={() => setSelectedItem(item)}
          >
            <div className="history-main">
              <div className="history-repo">
                <GitBranch size={16} />
                <span>{item.repo}</span>
              </div>
              <div className="history-date">
                <Calendar size={14} />
                <span>{item.date}</span>
              </div>
            </div>
            <div className="history-stats">
              <span className={`stat-badge ${item.status}`}>
                {item.confirmed > 0 && <AlertTriangle size={12} />}
                {item.confirmed === 0 && item.lowProb > 0 && <AlertCircle size={12} />}
                {item.confirmed === 0 && item.lowProb === 0 && <CheckCircle size={12} />}
                {item.confirmed} / {item.lowProb} / {item.safe}
              </span>
            </div>
          </div>
        ))}
      </div>
      {selectedItem && (
        <div className="history-detail">
          <h4>Scan Details</h4>
          <div className="detail-grid">
            <div className="detail-item">
              <span className="label">Repository</span>
              <span className="value mono">{selectedItem.repo}</span>
            </div>
            <div className="detail-item">
              <span className="label">Scan Date</span>
              <span className="value">{selectedItem.date}</span>
            </div>
            <div className="detail-item danger">
              <span className="label">Confirmed</span>
              <span className="value">{selectedItem.confirmed}</span>
            </div>
            <div className="detail-item warning">
              <span className="label">Low Probability</span>
              <span className="value">{selectedItem.lowProb}</span>
            </div>
            <div className="detail-item success">
              <span className="label">Safe</span>
              <span className="value">{selectedItem.safe}</span>
            </div>
          </div>
          <button className="view-full-btn">
            <Eye size={16} />
            View Full Report
          </button>
        </div>
      )}
    </div>
  );
};

// 2. Agent Comparison Component
const AgentComparison = () => {
  const { vulnerability, agents } = mockAgentComparison;

  const AgentCard = ({ name, icon: Icon, data, color }) => (
    <div className={`agent-card ${color}`}>
      <div className="agent-header">
        <Icon size={20} />
        <span>{name}</span>
        <span className={`verdict ${data.verdict ? 'vulnerable' : 'safe'}`}>
          {data.verdict ? <AlertTriangle size={14} /> : <CheckCircle size={14} />}
          {data.verdict ? 'VULNERABLE' : 'SAFE'}
        </span>
      </div>
      <div className="agent-metrics">
        <div className="metric">
          <span className="metric-label">Confidence</span>
          <div className="confidence-bar">
            <div className="confidence-fill" style={{ width: `${data.confidence * 100}%` }} />
          </div>
          <span className="metric-value">{(data.confidence * 100).toFixed(0)}%</span>
        </div>
        <div className="metric">
          <span className="metric-label">Risk Level</span>
          <span className={`risk-badge ${data.riskLevel.toLowerCase()}`}>{data.riskLevel}</span>
        </div>
      </div>
      <div className="agent-reasoning">
        <h5>Analysis</h5>
        <p>{data.reasoning}</p>
      </div>
      <div className="agent-recommendation">
        <h5>Recommendation</h5>
        <p>{data.recommendation}</p>
      </div>
    </div>
  );

  return (
    <div className="comparison-container">
      <div className="comparison-header">
        <FileCode size={18} />
        <span className="vuln-title">{vulnerability}</span>
      </div>
      <div className="agents-comparison-grid">
        <AgentCard name="OpenAI GPT-4.1" icon={Bot} data={agents.openai} color="green" />
        <AgentCard name="Claude Sonnet" icon={Brain} data={agents.claude} color="purple" />
        <AgentCard name="CodeBERT ML" icon={Zap} data={agents.localML} color="orange" />
      </div>
      <div className="disagreement-note">
        <Lightbulb size={16} />
        <span>All agents agree on vulnerability detection. Confidence variance: 16%</span>
      </div>
    </div>
  );
};

// 3. Metrics Dashboard Component
const MetricsDashboard = () => {
  const { overall, byAgent, confusionMatrix, vulnTypes } = mockMetrics;

  return (
    <div className="metrics-container">
      <div className="metrics-overview">
        <div className="metric-card highlight">
          <Gauge size={24} />
          <div className="metric-info">
            <span className="metric-value">{(overall.precision * 100).toFixed(1)}%</span>
            <span className="metric-label">Precision</span>
          </div>
        </div>
        <div className="metric-card highlight">
          <Target size={24} />
          <div className="metric-info">
            <span className="metric-value">{(overall.recall * 100).toFixed(1)}%</span>
            <span className="metric-label">Recall</span>
          </div>
        </div>
        <div className="metric-card highlight">
          <TrendingUp size={24} />
          <div className="metric-info">
            <span className="metric-value">{(overall.f1Score * 100).toFixed(1)}%</span>
            <span className="metric-label">F1 Score</span>
          </div>
        </div>
        <div className="metric-card highlight">
          <CheckCircle size={24} />
          <div className="metric-info">
            <span className="metric-value">{(overall.accuracy * 100).toFixed(1)}%</span>
            <span className="metric-label">Accuracy</span>
          </div>
        </div>
      </div>

      <div className="metrics-details">
        <div className="confusion-matrix">
          <h4>Confusion Matrix</h4>
          <div className="matrix-grid">
            <div className="matrix-cell tp">
              <span className="cell-value">{confusionMatrix.tp}</span>
              <span className="cell-label">True Positive</span>
            </div>
            <div className="matrix-cell fp">
              <span className="cell-value">{confusionMatrix.fp}</span>
              <span className="cell-label">False Positive</span>
            </div>
            <div className="matrix-cell fn">
              <span className="cell-value">{confusionMatrix.fn}</span>
              <span className="cell-label">False Negative</span>
            </div>
            <div className="matrix-cell tn">
              <span className="cell-value">{confusionMatrix.tn}</span>
              <span className="cell-label">True Negative</span>
            </div>
          </div>
        </div>

        <div className="agent-performance">
          <h4>Agent Performance</h4>
          <div className="agent-perf-list">
            {Object.entries(byAgent).map(([agent, data]) => (
              <div key={agent} className="agent-perf-item">
                <div className="agent-name">
                  {agent === 'openai' && <Bot size={16} />}
                  {agent === 'claude' && <Brain size={16} />}
                  {agent === 'localML' && <Zap size={16} />}
                  <span>{agent === 'openai' ? 'GPT-4.1' : agent === 'claude' ? 'Claude' : 'CodeBERT'}</span>
                </div>
                <div className="perf-bars">
                  <div className="perf-bar">
                    <span>P: {(data.precision * 100).toFixed(0)}%</span>
                    <div className="bar"><div style={{ width: `${data.precision * 100}%` }} /></div>
                  </div>
                  <div className="perf-bar">
                    <span>R: {(data.recall * 100).toFixed(0)}%</span>
                    <div className="bar"><div style={{ width: `${data.recall * 100}%` }} /></div>
                  </div>
                  <div className="perf-bar">
                    <span>F1: {(data.f1 * 100).toFixed(0)}%</span>
                    <div className="bar"><div style={{ width: `${data.f1 * 100}%` }} /></div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="vuln-detection-rates">
        <h4>Detection Rate by Vulnerability Type</h4>
        <div className="vuln-rates-list">
          {vulnTypes.map((v) => (
            <div key={v.type} className="vuln-rate-item">
              <span className="vuln-type">{v.type}</span>
              <div className="rate-bar">
                <div className="rate-fill" style={{ width: `${(v.detected / v.count) * 100}%` }} />
              </div>
              <span className="rate-value">{v.detected}/{v.count}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

// 4. Confidence Voting Component
const ConfidenceVoting = () => {
  const [votingMode, setVotingMode] = useState('weighted');

  return (
    <div className="voting-container">
      <div className="voting-modes">
        <button
          className={`mode-btn ${votingMode === 'majority' ? 'active' : ''}`}
          onClick={() => setVotingMode('majority')}
        >
          <Users size={16} />
          Majority Voting
        </button>
        <button
          className={`mode-btn ${votingMode === 'weighted' ? 'active' : ''}`}
          onClick={() => setVotingMode('weighted')}
        >
          <Gauge size={16} />
          Confidence-Weighted
        </button>
      </div>

      <div className="voting-demo">
        <div className="vote-example">
          <h4>Example: SQL Injection Detection</h4>
          <div className="votes-visual">
            <div className="vote-item">
              <Bot size={18} />
              <span>GPT-4.1</span>
              <span className="vote-verdict vulnerable">VULNERABLE</span>
              <span className="vote-conf">92%</span>
              {votingMode === 'weighted' && <span className="vote-weight">Weight: 0.92</span>}
            </div>
            <div className="vote-item">
              <Brain size={18} />
              <span>Claude</span>
              <span className="vote-verdict vulnerable">VULNERABLE</span>
              <span className="vote-conf">88%</span>
              {votingMode === 'weighted' && <span className="vote-weight">Weight: 0.88</span>}
            </div>
            <div className="vote-item">
              <Zap size={18} />
              <span>CodeBERT</span>
              <span className="vote-verdict safe">SAFE</span>
              <span className="vote-conf">54%</span>
              {votingMode === 'weighted' && <span className="vote-weight">Weight: 0.54</span>}
            </div>
          </div>
          <div className="vote-result">
            {votingMode === 'majority' ? (
              <>
                <span className="result-label">Majority Vote (2/3):</span>
                <span className="result-value vulnerable">VULNERABLE</span>
              </>
            ) : (
              <>
                <span className="result-label">Weighted Score:</span>
                <span className="result-calc">(0.92 + 0.88 - 0.54) / 3 = 0.42</span>
                <span className="result-value vulnerable">VULNERABLE (Threshold: 0.3)</span>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

// 5. Explainability Component
const ExplainabilityLayer = () => (
  <div className="explain-container">
    <div className="explain-demo">
      <div className="code-section">
        <h4>Vulnerable Code</h4>
        <pre className="code-block">
          <code>
{`def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"  # Line 45
    cursor.execute(query)
    return cursor.fetchone()`}
          </code>
        </pre>
        <div className="highlight-marker" style={{ top: '52px' }}>
          <AlertTriangle size={14} />
          Vulnerability detected here
        </div>
      </div>

      <div className="explain-section">
        <h4>Why Detected?</h4>
        <div className="explain-cards">
          <div className="explain-card">
            <div className="explain-header">
              <Code size={16} />
              <span>Pattern Match</span>
            </div>
            <p>String formatting (f-string) used directly in SQL query construction</p>
          </div>
          <div className="explain-card">
            <div className="explain-header">
              <ArrowRight size={16} />
              <span>Data Flow</span>
            </div>
            <p>user_id flows from function parameter → f-string → execute() without sanitization</p>
          </div>
          <div className="explain-card">
            <div className="explain-header">
              <AlertTriangle size={16} />
              <span>Risk Factor</span>
            </div>
            <p>No input validation, parameterization, or ORM usage detected in scope</p>
          </div>
        </div>
      </div>
    </div>
  </div>
);

// 6. Repo Scope Control Component
const RepoScopeControl = () => (
  <div className="scope-container">
    <div className="scope-controls">
      <div className="control-group">
        <label>
          <GitBranch size={16} />
          Branch
        </label>
        <select defaultValue="main">
          <option value="main">main</option>
          <option value="develop">develop</option>
          <option value="feature/auth">feature/auth</option>
          <option value="hotfix/security">hotfix/security</option>
        </select>
      </div>

      <div className="control-group">
        <label>
          <Filter size={16} />
          File Types
        </label>
        <div className="file-type-chips">
          <span className="chip active">Python</span>
          <span className="chip active">JavaScript</span>
          <span className="chip">Java</span>
          <span className="chip">Go</span>
          <span className="chip">C/C++</span>
        </div>
      </div>

      <div className="control-group">
        <label>
          <Layers size={16} />
          Scan Depth
        </label>
        <div className="depth-slider">
          <input type="range" min="1" max="3" defaultValue="2" />
          <div className="depth-labels">
            <span>Quick</span>
            <span>Standard</span>
            <span>Deep</span>
          </div>
        </div>
      </div>
    </div>

    <div className="scope-preview">
      <h4>Scan Preview</h4>
      <div className="preview-stats">
        <div className="preview-stat">
          <FileCode size={18} />
          <span>247 files</span>
        </div>
        <div className="preview-stat">
          <Code size={18} />
          <span>~45,000 LOC</span>
        </div>
        <div className="preview-stat">
          <Clock size={18} />
          <span>~3 min</span>
        </div>
      </div>
    </div>
  </div>
);

// 7. Custom Model Management Component
const ModelManagement = () => (
  <div className="model-container">
    <div className="model-card main">
      <div className="model-header">
        <Cpu size={24} />
        <div>
          <h4>{mockModelInfo.name}</h4>
          <span className="version">v{mockModelInfo.version}</span>
        </div>
        <span className="status-badge active">Active</span>
      </div>
      <div className="model-stats">
        <div className="model-stat">
          <span className="stat-label">Training Size</span>
          <span className="stat-value">{mockModelInfo.trainingSize}</span>
        </div>
        <div className="model-stat">
          <span className="stat-label">Last Trained</span>
          <span className="stat-value">{mockModelInfo.lastTrained}</span>
        </div>
        <div className="model-stat">
          <span className="stat-label">Accuracy</span>
          <span className="stat-value">{mockModelInfo.accuracy}</span>
        </div>
        <div className="model-stat">
          <span className="stat-label">Parameters</span>
          <span className="stat-value">{mockModelInfo.parameters}</span>
        </div>
      </div>
      <div className="model-languages">
        <span className="label">Supported Languages:</span>
        <div className="lang-chips">
          {mockModelInfo.languages.map(lang => (
            <span key={lang} className="lang-chip">{lang}</span>
          ))}
        </div>
      </div>
      <div className="model-actions">
        <button className="action-btn">
          <RefreshCw size={16} />
          Retrain
        </button>
        <button className="action-btn">
          <Settings size={16} />
          Configure
        </button>
      </div>
    </div>
  </div>
);

// 8. Risk Scoring Component
const RiskScoring = () => {
  const risks = [
    { name: 'SQL Injection', score: 9.2, color: '#DC2626' },
    { name: 'Weak Crypto', score: 7.5, color: '#F59E0B' },
    { name: 'XSS', score: 6.8, color: '#F59E0B' },
    { name: 'Path Traversal', score: 5.4, color: '#3B82F6' },
    { name: 'Info Disclosure', score: 3.2, color: '#22C55E' }
  ];

  return (
    <div className="risk-container">
      <div className="risk-list">
        {risks.map((risk, index) => (
          <div key={index} className="risk-item">
            <div className="risk-info">
              <span className="risk-name">{risk.name}</span>
              <span className="risk-score" style={{ color: risk.color }}>{risk.score}</span>
            </div>
            <div className="risk-bar">
              <div
                className="risk-fill"
                style={{
                  width: `${risk.score * 10}%`,
                  backgroundColor: risk.color
                }}
              />
            </div>
          </div>
        ))}
      </div>
      <div className="risk-legend">
        <div className="legend-item critical">
          <span className="dot" />
          <span>Critical (8-10)</span>
        </div>
        <div className="legend-item high">
          <span className="dot" />
          <span>High (6-8)</span>
        </div>
        <div className="legend-item medium">
          <span className="dot" />
          <span>Medium (4-6)</span>
        </div>
        <div className="legend-item low">
          <span className="dot" />
          <span>Low (0-4)</span>
        </div>
      </div>
    </div>
  );
};

// 9. CI/CD Integration Component
const CICDIntegration = () => (
  <div className="cicd-container">
    <div className="cicd-badge">
      <Workflow size={32} />
      <div>
        <h4>GitHub Actions Ready</h4>
        <p>One-click integration with your CI/CD pipeline</p>
      </div>
      <span className="available-badge">Available</span>
    </div>

    <div className="workflow-preview">
      <h4>Workflow Example</h4>
      <pre className="yaml-block">
{`name: Security Scan
on: [push, pull_request]

jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: AI Security Scan
        uses: ai-auditor/scan-action@v1
        with:
          agents: openai,claude,codebert
          fail-on: confirmed
      - name: Upload Report
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: ai_analysis.json`}
      </pre>
    </div>

    <div className="integration-features">
      <div className="int-feature">
        <CheckCircle size={16} />
        <span>Auto-scan on every PR</span>
      </div>
      <div className="int-feature">
        <CheckCircle size={16} />
        <span>Block merge on critical findings</span>
      </div>
      <div className="int-feature">
        <CheckCircle size={16} />
        <span>Slack/Discord notifications</span>
      </div>
      <div className="int-feature">
        <CheckCircle size={16} />
        <span>SARIF output for GitHub Security tab</span>
      </div>
    </div>
  </div>
);

// Main Future Page Component
function FuturePage({ onBack }) {
  const [openSections, setOpenSections] = useState({
    history: true,
    comparison: false,
    metrics: false,
    voting: false,
    explain: false,
    scope: false,
    model: false,
    risk: false,
    cicd: false
  });

  const toggleSection = (key) => {
    setOpenSections(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const features = [
    { key: 'history', icon: History, title: 'Analysis History', badge: 'Phase 2', component: AnalysisHistory },
    { key: 'comparison', icon: GitCompare, title: 'Agent Comparison View', badge: 'Phase 2', component: AgentComparison },
    { key: 'metrics', icon: BarChart3, title: 'Accuracy & Metrics Dashboard', badge: 'Phase 2', component: MetricsDashboard },
    { key: 'voting', icon: Vote, title: 'Confidence-Aware Voting', badge: 'Phase 2', component: ConfidenceVoting },
    { key: 'explain', icon: Lightbulb, title: 'Explainability Layer', badge: 'Phase 2', component: ExplainabilityLayer },
    { key: 'scope', icon: GitBranch, title: 'Repo Scope Control', badge: 'Phase 2', component: RepoScopeControl },
    { key: 'model', icon: Cpu, title: 'Custom Model Management', badge: 'Phase 2', component: ModelManagement },
    { key: 'risk', icon: AlertTriangle, title: 'Risk-Based Severity Scoring', badge: 'Phase 2', component: RiskScoring },
    { key: 'cicd', icon: Workflow, title: 'CI/CD Integration', badge: 'Phase 2', component: CICDIntegration }
  ];

  return (
    <div className="future-page">
      <header className="future-header">
        <button className="back-btn" onClick={onBack}>
          <ArrowRight size={20} style={{ transform: 'rotate(180deg)' }} />
          Back to Scanner
        </button>
        <div className="future-title">
          <Star className="star-icon" />
          <h1>Future Roadmap</h1>
          <span className="subtitle">Phase 2</span>
        </div>
      </header>

      <main className="future-content">
        <div className="roadmap-intro">
          <div className="intro-card">
            <Lock size={24} />
            <div>
              <h3>Multi-Agent Security Analysis Platform</h3>
              <p>Advanced features for comprehensive vulnerability detection, analysis, and DevSecOps integration</p>
            </div>
          </div>
        </div>

        <div className="features-list">
          {features.map(({ key, icon, title, badge, component: Component }) => (
            <FeatureSection
              key={key}
              icon={icon}
              title={title}
              badge={badge}
              isOpen={openSections[key]}
              onToggle={() => toggleSection(key)}
            >
              <Component />
            </FeatureSection>
          ))}
        </div>
      </main>

      <footer className="future-footer">
        <p>AI Security Auditor - Roadmap Preview for SD-II</p>
      </footer>
    </div>
  );
}

export default FuturePage;
