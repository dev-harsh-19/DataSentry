import { useEffect, useState } from 'react';

const API_BASE = 'http://localhost:5000';

async function apiRequest(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  const text = await response.text();
  const data = text ? JSON.parse(text) : {};
  if (!response.ok) {
    throw new Error(data.message || 'Request failed');
  }
  return data;
}

function Badge({ label, value }) {
  const riskMap = {
    HIGH: 'badge badge-high',
    MEDIUM: 'badge badge-medium',
    LOW: 'badge badge-low',
    'NON-SENSITIVE': 'badge badge-neutral',
  };
  return (
    <span className={riskMap[value] || 'badge badge-neutral'}>{label || value}</span>
  );
}

function LoginPage({ onLogin }) {
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('admin123');
  const [error, setError] = useState('');

  async function handleSubmit(event) {
    event.preventDefault();
    try {
      const data = await apiRequest('/api/login', {
        method: 'POST',
        body: JSON.stringify({ username, password }),
      });
      localStorage.setItem('datasentry-user', data.username);
      onLogin(data.username);
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <div className="login-shell">
      <div className="login-card">
        <div className="login-header">
          <div className="brand-mark">D</div>
          <div>
            <h1>DataSentry</h1>
            <p>Database Security and Privacy Hub</p>
          </div>
        </div>
        <form onSubmit={handleSubmit} className="login-form">
          <label>
            Username
            <input value={username} onChange={(e) => setUsername(e.target.value)} />
          </label>
          <label>
            Password
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
          </label>
          {error && <div className="error-box">{error}</div>}
          <button type="submit" className="primary-button">Login</button>
        </form>
      </div>
    </div>
  );
}

function StatCard({ title, value, accent }) {
  return (
    <div className="stat-card">
      <div className="stat-label">{title}</div>
      <div className={`stat-value ${accent}`}>{value}</div>
    </div>
  );
}

function DashboardPage({ summary, results }) {
  return (
    <div>
      <div className="page-header">
        <div>
          <span className="eyebrow">Security Overview</span>
          <h2>Privacy Dashboard</h2>
        </div>
      </div>

      <div className="stats-grid">
        <StatCard title="Total Tables Scanned" value={summary.total_tables || 0} accent="blue" />
        <StatCard title="Total Columns Analyzed" value={summary.total_columns || 0} accent="blue" />
        <StatCard title="Sensitive Columns Found" value={summary.sensitive_columns || 0} accent="red" />
        <StatCard title="High Risk" value={summary.high_risk || 0} accent="red" />
        <StatCard title="Medium Risk" value={summary.medium_risk || 0} accent="orange" />
        <StatCard title="Low Risk" value={summary.low_risk || 0} accent="green" />
      </div>

      <div className="panel-grid two-col">
        <div className="panel">
          <h3>Sensitive Data Distribution</h3>
          <div className="chart-box">
            <div className="chart-row"><span>High</span><div className="bar bar-red" style={{ width: `${Math.max((summary.high_risk || 0) * 20, 10)}%` }}>{summary.high_risk || 0}</div></div>
            <div className="chart-row"><span>Medium</span><div className="bar bar-orange" style={{ width: `${Math.max((summary.medium_risk || 0) * 20, 10)}%` }}>{summary.medium_risk || 0}</div></div>
            <div className="chart-row"><span>Low</span><div className="bar bar-green" style={{ width: `${Math.max((summary.low_risk || 0) * 20, 10)}%` }}>{summary.low_risk || 0}</div></div>
          </div>
        </div>

        <div className="panel">
          <h3>Latest Scan Findings</h3>
          <div className="results-list">
            {results.slice(0, 6).map((item, idx) => (
              <div key={`${item.table_name}-${item.column_name}-${idx}`} className="result-row">
                <span>{item.table_name}.{item.column_name}</span>
                <Badge label={item.detected_type} value={item.risk_level} />
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function ConnectionPage() {
  const [form, setForm] = useState({ connection_name: 'Primary DB', host: 'localhost', username: 'root', password: '', database_name: '' });
  const [message, setMessage] = useState('');
  const [savedConnections, setSavedConnections] = useState([]);

  async function fetchConnections() {
    const data = await apiRequest('/api/connections');
    setSavedConnections(data.connections || []);
  }

  useEffect(() => {
    fetchConnections();
  }, []);

  async function handleTestConnection() {
    try {
      const data = await apiRequest('/api/test-connection', {
        method: 'POST',
        body: JSON.stringify(form),
      });
      setMessage(data.message);
    } catch (err) {
      setMessage(err.message);
    }
  }

  async function handleSaveConnection() {
    try {
      const data = await apiRequest('/api/connections', {
        method: 'POST',
        body: JSON.stringify(form),
      });
      setMessage(data.message);
      fetchConnections();
    } catch (err) {
      setMessage(err.message);
    }
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <span className="eyebrow">Database Connection</span>
          <h2>Connect to MySQL Database</h2>
        </div>
      </div>

      <div className="panel">
        <div className="form-grid">
          <label>Connection Name<input value={form.connection_name} onChange={(e) => setForm({ ...form, connection_name: e.target.value })} /></label>
          <label>Host<input value={form.host} onChange={(e) => setForm({ ...form, host: e.target.value })} /></label>
          <label>Username<input value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} /></label>
          <label>Password<input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} /></label>
          <label className="full-width">Database Name<input value={form.database_name} onChange={(e) => setForm({ ...form, database_name: e.target.value })} /></label>
        </div>
        <div className="button-row">
          <button className="primary-button" onClick={handleTestConnection}>Test Connection</button>
          <button className="secondary-button" onClick={handleSaveConnection}>Save Connection</button>
        </div>
        {message && <div className="status-box">{message}</div>}
      </div>

      <div className="panel mt-16">
        <h3>Saved Connections</h3>
        <table className="data-table">
          <thead>
            <tr>
              <th>Connection</th>
              <th>Host</th>
              <th>Database</th>
            </tr>
          </thead>
          <tbody>
            {savedConnections.length ? savedConnections.map((item) => (
              <tr key={item.id}><td>{item.connection_name}</td><td>{item.host}</td><td>{item.database_name}</td></tr>
            )) : <tr><td colSpan="3">No database connections stored yet.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function ScannerPage({ onScanComplete }) {
  const [form, setForm] = useState({ host: 'localhost', username: 'root', password: '', database_name: '' });
  const [results, setResults] = useState([]);
  const [summary, setSummary] = useState({ total_tables: 0, total_columns: 0, sensitive_columns: 0, high_risk: 0, medium_risk: 0, low_risk: 0 });
  const [message, setMessage] = useState('');
  const [newColumns, setNewColumns] = useState([]);

  async function handleScan() {
    try {
      const data = await apiRequest('/api/scan', {
        method: 'POST',
        body: JSON.stringify(form),
      });
      setSummary(data.summary);
      setResults(data.results);
      setNewColumns(data.new_columns || []);
      onScanComplete?.(data.results || []);
      setMessage(data.message);
    } catch (err) {
      setMessage(err.message);
    }
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <span className="eyebrow">Database Scanner</span>
          <h2>Scan and classify sensitive columns</h2>
        </div>
      </div>

      <div className="panel">
        <div className="form-grid">
          <label>Host<input value={form.host} onChange={(e) => setForm({ ...form, host: e.target.value })} /></label>
          <label>Username<input value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} /></label>
          <label>Password<input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} /></label>
          <label>Database Name<input value={form.database_name} onChange={(e) => setForm({ ...form, database_name: e.target.value })} /></label>
        </div>
        <div className="button-row">
          <button className="primary-button" onClick={handleScan}>Run Scan</button>
        </div>
        {message && <div className="status-box">{message}</div>}
      </div>

      <div className="stats-grid small-grid">
        <StatCard title="Tables" value={summary.total_tables || 0} accent="blue" />
        <StatCard title="Columns" value={summary.total_columns || 0} accent="blue" />
        <StatCard title="Sensitive" value={summary.sensitive_columns || 0} accent="red" />
        <StatCard title="High" value={summary.high_risk || 0} accent="red" />
        <StatCard title="Medium" value={summary.medium_risk || 0} accent="orange" />
        <StatCard title="Low" value={summary.low_risk || 0} accent="green" />
      </div>

      {newColumns.length > 0 && (
        <div className="panel mt-16">
          <h3>New Columns Detected</h3>
          <ul className="bullet-list">
            {newColumns.map((item, index) => (
              <li key={`${item.table_name}-${item.column_name}-${index}`}>
                {item.table_name}.{item.column_name} — <Badge label={item.detected_type} value={item.risk_level} />
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="panel mt-16">
        <h3>Scan Results</h3>
        <table className="data-table">
          <thead>
            <tr>
              <th>Table</th>
              <th>Column</th>
              <th>Detected Type</th>
              <th>Risk</th>
              <th>Recommendation</th>
            </tr>
          </thead>
          <tbody>
            {results.length ? results.map((item, index) => (
              <tr key={`${item.table_name}-${item.column_name}-${index}`}>
                <td>{item.table_name}</td>
                <td>{item.column_name}</td>
                <td>{item.detected_type}</td>
                <td><Badge value={item.risk_level} /></td>
                <td>{item.recommendation}</td>
              </tr>
            )) : <tr><td colSpan="5">Run a scan to view detected sensitive columns.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function ResultsPage({ results }) {
  return (
    <div>
      <div className="page-header">
        <div>
          <span className="eyebrow">Scan Results</span>
          <h2>Detected sensitive data</h2>
        </div>
      </div>
      <div className="panel">
        <table className="data-table">
          <thead>
            <tr>
              <th>Table</th>
              <th>Column</th>
              <th>Detected Type</th>
              <th>Risk Level</th>
              <th>Classification Reason</th>
            </tr>
          </thead>
          <tbody>
            {results.length ? results.map((item, index) => (
              <tr key={`${item.table_name}-${item.column_name}-${index}`}>
                <td>{item.table_name}</td>
                <td>{item.column_name}</td>
                <td>{item.detected_type}</td>
                <td><Badge value={item.risk_level} /></td>
                <td>{item.classification_reason}</td>
              </tr>
            )) : <tr><td colSpan="5">No scan results to display yet.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function RecommendationsPage({ results }) {
  return (
    <div>
      <div className="page-header">
        <div>
          <span className="eyebrow">Privacy Recommendations</span>
          <h2>Protection guidance for sensitive fields</h2>
        </div>
      </div>
      <div className="panel">
        {results.length ? (
          <div className="recommendation-list">
            {results.map((item, index) => (
              <div key={`${item.table_name}-${item.column_name}-${index}`} className="recommendation-card">
                <div className="recommendation-top">
                  <strong>{item.table_name}.{item.column_name}</strong>
                  <Badge value={item.risk_level} />
                </div>
                <div className="recommendation-meta">Detected as {item.detected_type}</div>
                <div>{item.recommendation}</div>
              </div>
            ))}
          </div>
        ) : <p>No recommendations available until a scan is run.</p>}
      </div>
    </div>
  );
}

function MaskingPage() {
  const [samples, setSamples] = useState(['harsh@gmail.com', '9876543210', '4532015112830366']);
  const [selectedType, setSelectedType] = useState('Email Address');
  const [masked, setMasked] = useState([]);

  async function handleMasking() {
    try {
      const data = await apiRequest('/api/mask-demo', {
        method: 'POST',
        body: JSON.stringify({ detected_type: selectedType, samples }),
      });
      setMasked(data.masked);
    } catch (err) {
      setMasked([]);
    }
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <span className="eyebrow">Masking Demo</span>
          <h2>Preview data masking rules</h2>
        </div>
      </div>

      <div className="panel">
        <div className="form-grid">
          <label>Detected Type
            <select value={selectedType} onChange={(e) => setSelectedType(e.target.value)}>
              <option>Email Address</option>
              <option>Phone Number</option>
              <option>Card Number</option>
              <option>Password</option>
              <option>Aadhaar-like Identifier</option>
            </select>
          </label>
          <label className="full-width">Sample Values
            <textarea value={samples.join('\n')} onChange={(e) => setSamples(e.target.value.split('\n').filter(Boolean))} rows="6" />
          </label>
        </div>
        <div className="button-row"><button className="primary-button" onClick={handleMasking}>Apply Mask</button></div>
      </div>

      {masked.length > 0 && (
        <div className="panel mt-16">
          <h3>Masked Results</h3>
          <table className="data-table">
            <thead><tr><th>Original</th><th>Masked</th></tr></thead>
            <tbody>
              {samples.map((item, index) => (
                <tr key={`${item}-${index}`}>
                  <td>{item}</td>
                  <td>{masked[index]}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function ReportsPage() {
  const [history, setHistory] = useState([]);

  async function loadHistory() {
    const data = await apiRequest('/api/history');
    setHistory(data.history || []);
  }

  useEffect(() => {
    loadHistory();
  }, []);

  function handleDownload(scanId) {
    window.open(`${API_BASE}/api/reports/export?scan_id=${scanId}`, '_blank');
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <span className="eyebrow">Scan Reports</span>
          <h2>Previous scan history</h2>
        </div>
      </div>

      <div className="panel">
        <table className="data-table">
          <thead>
            <tr>
              <th>Database</th>
              <th>Tables</th>
              <th>Columns</th>
              <th>Sensitive</th>
              <th>Scan Date</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {history.length ? history.map((item) => (
              <tr key={item.id}>
                <td>{item.database_name}</td>
                <td>{item.total_tables}</td>
                <td>{item.total_columns}</td>
                <td>{item.sensitive_columns}</td>
                <td>{item.scan_date}</td>
                <td><button className="secondary-button small" onClick={() => handleDownload(item.id)}>CSV</button></td>
              </tr>
            )) : <tr><td colSpan="6">No scan history available.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default function App() {
  const [user, setUser] = useState(localStorage.getItem('datasentry-user') || '');
  const [page, setPage] = useState('dashboard');
  const [dashboardSummary, setDashboardSummary] = useState({ total_tables: 0, total_columns: 0, sensitive_columns: 0, high_risk: 0, medium_risk: 0, low_risk: 0 });
  const [dashboardResults, setDashboardResults] = useState([]);
  const [scanResults, setScanResults] = useState([]);

  useEffect(() => {
    if (!user) return;
    async function loadDashboard() {
      try {
        const data = await apiRequest('/api/dashboard');
        setDashboardSummary(data.summary || { total_tables: 0, total_columns: 0, sensitive_columns: 0, high_risk: 0, medium_risk: 0, low_risk: 0 });
        setDashboardResults(data.results || []);
        setScanResults((current) => current.length ? current : data.results || []);
      } catch (error) {
        console.error(error);
      }
    }
    loadDashboard();
  }, [user, page]);

  function logout() {
    localStorage.removeItem('datasentry-user');
    setUser('');
    setPage('dashboard');
  }

  if (!user) {
    return <LoginPage onLogin={setUser} />;
  }

  const navItems = [
    { id: 'dashboard', label: 'Dashboard' },
    { id: 'connection', label: 'Database Connection' },
    { id: 'scanner', label: 'Database Scanner' },
    { id: 'results', label: 'Scan Results' },
    { id: 'recommendations', label: 'Privacy Recommendations' },
    { id: 'masking', label: 'Masking Demo' },
    { id: 'reports', label: 'Reports' },
  ];

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-row">
          <div className="brand-mark">D</div>
          <div>
            <div className="brand-title">DataSentry</div>
            <div className="brand-subtitle">Secure Discovery</div>
          </div>
        </div>

        <nav className="nav-menu">
          {navItems.map((item) => (
            <button key={item.id} className={page === item.id ? 'nav-item active' : 'nav-item'} onClick={() => setPage(item.id)}>
              {item.label}
            </button>
          ))}
        </nav>

        <button className="logout-button" onClick={logout}>Logout</button>
      </aside>

      <main className="content-area">
        {page === 'dashboard' && <DashboardPage summary={dashboardSummary} results={dashboardResults} />}
        {page === 'connection' && <ConnectionPage />}
        {page === 'scanner' && <ScannerPage onScanComplete={setScanResults} />}
        {page === 'results' && <ResultsPage results={scanResults} />}
        {page === 'recommendations' && <RecommendationsPage results={scanResults} />}
        {page === 'masking' && <MaskingPage />}
        {page === 'reports' && <ReportsPage />}
      </main>
    </div>
  );
}
