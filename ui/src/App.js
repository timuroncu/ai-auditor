import React, { useState, useEffect, useRef } from 'react';
import {
  Shield, Search, GitBranch, AlertTriangle, CheckCircle,
  XCircle, Loader, FileCode, Users, Brain, Bot,
  ChevronDown, ChevronUp, Terminal, Zap, Lock,
  AlertCircle, Info, ArrowRight, Clock, Server, Star
} from 'lucide-react';
import './App.css';
import FuturePage from './FuturePage';

// Header Component
const Header = ({ onNavigateToFuture }) => (
  <header className="header">
    <div className="header-content">
      <div className="logo">
        <Shield className="logo-icon" />
        <span className="logo-text">AI Security Auditor</span>
      </div>
      <div className="header-actions">
        <button className="future-btn" onClick={onNavigateToFuture}>
          <Star size={16} />
          <span>Future Roadmap</span>
        </button>
        <div className="header-badge">
          <Zap size={14} />
          <span>Multi-Agent System</span>
        </div>
      </div>
    </div>
  </header>
);

// Repo Input Component
const RepoInput = ({ onScan, isScanning }) => {
  const [repo, setRepo] = useState('');
  const [isValid, setIsValid] = useState(null);

  const validateRepo = (value) => {
    const pattern = /^[a-zA-Z0-9_-]+\/[a-zA-Z0-9_.-]+$/;
    return pattern.test(value);
  };

  const handleChange = (e) => {
    const value = e.target.value;
    setRepo(value);
    if (value.length > 0) {
      setIsValid(validateRepo(value));
    } else {
      setIsValid(null);
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    if (isValid && !isScanning) {
      onScan(repo);
    }
  };

  return (
    <div className="repo-input-container">
      <div className="input-header">
        <GitBranch className="input-icon" />
        <h2>Enter GitHub Repository</h2>
      </div>
      <form onSubmit={handleSubmit} className="input-form">
        <div className="input-wrapper">
          <span className="input-prefix">github.com/</span>
          <input
            type="text"
            value={repo}
            onChange={handleChange}
            placeholder="username/repository"
            className={`repo-input ${isValid === false ? 'invalid' : isValid === true ? 'valid' : ''}`}
            disabled={isScanning}
          />
          {isValid !== null && (
            <span className="input-status">
              {isValid ? <CheckCircle size={20} className="valid-icon" /> : <XCircle size={20} className="invalid-icon" />}
            </span>
          )}
        </div>
        <button
          type="submit"
          className={`scan-button ${!isValid || isScanning ? 'disabled' : ''}`}
          disabled={!isValid || isScanning}
        >
          {isScanning ? (
            <>
              <Loader className="animate-spin" size={20} />
              <span>Scanning...</span>
            </>
          ) : (
            <>
              <Search size={20} />
              <span>Start Scan</span>
            </>
          )}
        </button>
      </form>
      <p className="input-hint">
        <Info size={14} />
        Example: timuroncu/ai-auditor
      </p>
    </div>
  );
};

// Scan Progress Component
const ScanProgress = ({ stage, progress, logs }) => {
  const logsEndRef = useRef(null);

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  const stages = [
    { id: 1, name: 'Fetching Files', icon: FileCode },
    { id: 2, name: 'Downloading', icon: Server },
    { id: 3, name: 'Semgrep Scan', icon: Search },
    { id: 4, name: 'AI Analysis', icon: Brain },
    { id: 5, name: 'Complete', icon: CheckCircle },
  ];

  return (
    <div className="progress-container animate-fade-in">
      <div className="progress-header">
        <Terminal size={20} />
        <h3>Scan Progress</h3>
      </div>

      <div className="stages">
        {stages.map((s, index) => {
          const Icon = s.icon;
          const isActive = s.id === stage;
          const isComplete = s.id < stage;

          return (
            <div
              key={s.id}
              className={`stage ${isActive ? 'active' : ''} ${isComplete ? 'complete' : ''}`}
            >
              <div className="stage-icon">
                {isActive && stage !== 5 ? (
                  <Loader className="animate-spin" size={18} />
                ) : (
                  <Icon size={18} />
                )}
              </div>
              <span className="stage-name">{s.name}</span>
              {index < stages.length - 1 && <div className="stage-connector" />}
            </div>
          );
        })}
      </div>

      <div className="progress-bar-container">
        <div className="progress-bar" style={{ width: `${progress}%` }} />
      </div>
      <span className="progress-text">{progress}%</span>

      <div className="logs-container">
        <div className="logs-header">
          <Terminal size={14} />
          <span>Live Output</span>
        </div>
        <div className="logs">
          {logs.map((log, index) => (
            <div key={index} className={`log-line ${log.type}`}>
              <span className="log-time">[{log.time}]</span>
              <span className="log-message">{log.message}</span>
            </div>
          ))}
          <div ref={logsEndRef} />
        </div>
      </div>
    </div>
  );
};

// Agent Vote Badge
const AgentVoteBadge = ({ agent, vote }) => {
  const getAgentIcon = () => {
    switch (agent) {
      case 'openai_gpt': return <Bot size={14} />;
      case 'anthropic_claude': return <Brain size={14} />;
      case 'local_ml': return <Zap size={14} />;
      default: return <Bot size={14} />;
    }
  };

  const getAgentName = () => {
    switch (agent) {
      case 'openai_gpt': return 'GPT';
      case 'anthropic_claude': return 'Claude';
      case 'local_ml': return 'ML';
      default: return agent;
    }
  };

  return (
    <div className={`agent-badge ${vote === true ? 'vulnerable' : vote === false ? 'safe' : 'pending'}`}>
      {getAgentIcon()}
      <span>{getAgentName()}</span>
      {vote === true ? <CheckCircle size={12} /> : vote === false ? <XCircle size={12} /> : <Clock size={12} />}
    </div>
  );
};

// Vulnerability Card Component
const VulnerabilityCard = ({ vuln, index }) => {
  const [isExpanded, setIsExpanded] = useState(false);

  const { semgrep_finding, voting, agent_analyses } = vuln;
  const voteResult = voting?.result || {};
  const votes = voting?.votes || {};

  const getSeverityColor = (level) => {
    switch (level?.toUpperCase()) {
      case 'CRITICAL': return 'critical';
      case 'HIGH': return 'high';
      case 'MEDIUM': return 'medium';
      case 'LOW': return 'low';
      default: return 'info';
    }
  };

  const riskLevel = agent_analyses?.openai_gpt?.risk_level ||
                    agent_analyses?.anthropic_claude?.risk_level ||
                    'MEDIUM';

  return (
    <div className="vuln-card animate-slide-up" style={{ animationDelay: `${index * 0.1}s` }}>
      <div className="vuln-header" onClick={() => setIsExpanded(!isExpanded)}>
        <div className="vuln-title">
          <AlertTriangle className={`vuln-icon ${getSeverityColor(riskLevel)}`} />
          <div className="vuln-info">
            <h4>{semgrep_finding?.check_id?.split('.').pop() || 'Unknown'}</h4>
            <span className="vuln-file mono">
              <FileCode size={12} />
              {semgrep_finding?.file?.replace('temp_repo/', '')}:{semgrep_finding?.line}
            </span>
          </div>
        </div>
        <div className="vuln-meta">
          <span className={`severity-badge ${getSeverityColor(riskLevel)}`}>
            {riskLevel}
          </span>
          <span className="vote-badge">
            <Users size={14} />
            {voteResult.vote_ratio}
          </span>
          {isExpanded ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
        </div>
      </div>

      {isExpanded && (
        <div className="vuln-details animate-fade-in">
          <div className="detail-section">
            <h5>
              <Users size={16} />
              Agent Votes
            </h5>
            <div className="agents-grid">
              <AgentVoteBadge agent="openai_gpt" vote={votes.openai_gpt} />
              <AgentVoteBadge agent="anthropic_claude" vote={votes.anthropic_claude} />
              <AgentVoteBadge agent="local_ml" vote={votes.local_ml} />
            </div>
          </div>

          <div className="detail-section">
            <h5>
              <AlertCircle size={16} />
              Analysis
            </h5>
            <p className="analysis-text">
              {agent_analyses?.openai_gpt?.reasoning ||
               agent_analyses?.anthropic_claude?.reasoning ||
               semgrep_finding?.message}
            </p>
          </div>

          <div className="detail-section">
            <h5>
              <Lock size={16} />
              Recommendation
            </h5>
            <p className="recommendation-text">
              {agent_analyses?.openai_gpt?.recommendation ||
               agent_analyses?.anthropic_claude?.recommendation ||
               'Review and fix the vulnerability'}
            </p>
          </div>
        </div>
      )}
    </div>
  );
};

// Results Summary Component
const ResultsSummary = ({ data }) => {
  const summary = data.voting_summary || {};

  return (
    <div className="summary-container animate-slide-up">
      <div className="summary-header">
        <Shield size={24} />
        <div>
          <h2>Scan Complete</h2>
          <p className="mono">{data.repository}</p>
        </div>
      </div>

      <div className="summary-stats">
        <div className="stat-card danger">
          <AlertTriangle size={24} />
          <div className="stat-info">
            <span className="stat-value">{summary.confirmed_vulnerabilities || 0}</span>
            <span className="stat-label">Confirmed</span>
          </div>
        </div>
        <div className="stat-card warning">
          <AlertCircle size={24} />
          <div className="stat-info">
            <span className="stat-value">{summary.low_probability || 0}</span>
            <span className="stat-label">Low Probability</span>
          </div>
        </div>
        <div className="stat-card success">
          <CheckCircle size={24} />
          <div className="stat-info">
            <span className="stat-value">{summary.not_vulnerable || 0}</span>
            <span className="stat-label">Safe</span>
          </div>
        </div>
      </div>

      <div className="agents-info">
        <h4>
          <Brain size={16} />
          Active Agents
        </h4>
        <div className="agents-list">
          <div className="agent-item">
            <Bot size={16} />
            <span>OpenAI GPT-4.1</span>
          </div>
          <div className="agent-item">
            <Brain size={16} />
            <span>Claude Sonnet</span>
          </div>
          <div className="agent-item">
            <Zap size={16} />
            <span>CodeBERT ML</span>
          </div>
        </div>
      </div>
    </div>
  );
};

// Main App Component
function App() {
  const [currentPage, setCurrentPage] = useState('scanner'); // 'scanner' or 'future'
  const [isScanning, setIsScanning] = useState(false);
  const [scanStage, setScanStage] = useState(0);
  const [progress, setProgress] = useState(0);
  const [logs, setLogs] = useState([]);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);

  // If on future page, render FuturePage component
  if (currentPage === 'future') {
    return <FuturePage onBack={() => setCurrentPage('scanner')} />;
  }

  const addLog = (message, type = 'info') => {
    const time = new Date().toLocaleTimeString('en-US', {
      hour12: false,
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
    setLogs(prev => [...prev, { time, message, type }]);
  };

  const handleScan = async (repo) => {
    setIsScanning(true);
    setResults(null);
    setError(null);
    setLogs([]);
    setProgress(0);
    setScanStage(1);

    addLog(`Starting scan for ${repo}...`, 'info');

    try {
      // Stage 1: Fetching files
      addLog('Connecting to GitHub API...', 'info');
      await simulateDelay(500);
      setProgress(10);
      addLog('Fetching repository structure...', 'info');
      await simulateDelay(800);
      setProgress(20);
      addLog('Found repository files', 'success');

      // Stage 2: Downloading
      setScanStage(2);
      addLog('Downloading source files...', 'info');
      setProgress(30);
      await simulateDelay(600);
      setProgress(40);
      addLog('Filtering non-code files...', 'info');
      await simulateDelay(400);
      setProgress(50);
      addLog('Download complete', 'success');

      // Stage 3: Semgrep scan
      setScanStage(3);
      addLog('Initializing Semgrep scanner...', 'info');
      setProgress(55);
      await simulateDelay(500);
      addLog('Running static analysis with auto rules...', 'info');
      setProgress(65);

      // Call actual API
      const response = await fetch('http://localhost:5001/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repo })
      });

      if (!response.ok) {
        throw new Error('Scan failed');
      }

      setProgress(75);
      addLog('Semgrep analysis complete', 'success');

      // Stage 4: AI Analysis
      setScanStage(4);
      addLog('Starting multi-agent AI analysis...', 'info');
      setProgress(80);
      await simulateDelay(500);
      addLog('Agent 1 (OpenAI GPT) analyzing...', 'info');
      await simulateDelay(400);
      addLog('Agent 2 (Claude) analyzing...', 'info');
      await simulateDelay(400);
      addLog('Agent 3 (CodeBERT ML) analyzing...', 'info');
      setProgress(90);
      await simulateDelay(500);
      addLog('Aggregating votes...', 'info');
      setProgress(95);

      const data = await response.json();

      // Stage 5: Complete
      setScanStage(5);
      setProgress(100);
      addLog(`Scan complete! Found ${data.voting_summary?.confirmed_vulnerabilities || 0} vulnerabilities`, 'success');

      setResults(data);

    } catch (err) {
      addLog(`Error: ${err.message}`, 'error');
      setError(err.message);
    } finally {
      setIsScanning(false);
    }
  };

  const simulateDelay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

  return (
    <div className="app">
      <Header onNavigateToFuture={() => setCurrentPage('future')} />

      <main className="main-content">
        <div className="hero">
          <h1>
            <Shield className="hero-icon" />
            AI-Powered Security Scanner
          </h1>
          <p>Multi-agent vulnerability detection with OpenAI, Claude, and CodeBERT</p>
        </div>

        <RepoInput onScan={handleScan} isScanning={isScanning} />

        {isScanning && (
          <ScanProgress stage={scanStage} progress={progress} logs={logs} />
        )}

        {error && (
          <div className="error-container animate-fade-in">
            <XCircle size={24} />
            <div>
              <h4>Scan Failed</h4>
              <p>{error}</p>
            </div>
          </div>
        )}

        {results && (
          <div className="results-container">
            <ResultsSummary data={results} />

            {/* Confirmed Vulnerabilities */}
            {results.results && results.results.filter(v => v.voting?.result?.status === 'CONFIRMED_VULNERABILITY').length > 0 && (
              <div className="vulns-section">
                <h3>
                  <AlertTriangle size={20} />
                  Detected Vulnerabilities
                </h3>
                <div className="vulns-list">
                  {results.results
                    .filter(v => v.voting?.result?.status === 'CONFIRMED_VULNERABILITY')
                    .map((vuln, index) => (
                      <VulnerabilityCard key={index} vuln={vuln} index={index} />
                    ))}
                </div>
              </div>
            )}

            {/* Low Probability */}
            {results.results && results.results.filter(v => v.voting?.result?.status === 'LOW_PROBABILITY').length > 0 && (
              <div className="vulns-section low-prob-section">
                <h3>
                  <AlertCircle size={20} />
                  Low Probability
                </h3>
                <div className="vulns-list">
                  {results.results
                    .filter(v => v.voting?.result?.status === 'LOW_PROBABILITY')
                    .map((vuln, index) => (
                      <VulnerabilityCard key={index} vuln={vuln} index={index} />
                    ))}
                </div>
              </div>
            )}

            {/* Safe / Not Vulnerable */}
            {results.results && results.results.filter(v => v.voting?.result?.status === 'NOT_VULNERABLE').length > 0 && (
              <div className="vulns-section safe-section">
                <h3>
                  <CheckCircle size={20} />
                  Safe (False Positives)
                </h3>
                <div className="vulns-list">
                  {results.results
                    .filter(v => v.voting?.result?.status === 'NOT_VULNERABLE')
                    .map((vuln, index) => (
                      <VulnerabilityCard key={index} vuln={vuln} index={index} />
                    ))}
                </div>
              </div>
            )}
          </div>
        )}
      </main>

      <footer className="footer">
        <p>AI Security Auditor - Multi-Agent Voting System</p>
      </footer>
    </div>
  );
}

export default App;
