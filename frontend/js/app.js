(function () {
  'use strict';

  var LS_KEY = 'lh_ehr_api_base';

  try {
    var stored = localStorage.getItem(LS_KEY);
    if (stored !== null && stored !== '') {
      window.API_BASE = stored;
    }
  } catch (e) {
    /* ignore */
  }

  if (location.protocol === 'file:' && (!window.API_BASE || String(window.API_BASE).trim() === '')) {
    window.API_BASE = 'http://127.0.0.1:8000';
  }

  function apiBase() {
    var b = typeof window.API_BASE === 'string' ? window.API_BASE.trim().replace(/\/$/, '') : '';
    return b;
  }

  function apiUrl(path) {
    path = String(path).replace(/^\//, '');
    var base = apiBase();
    if (base) {
      return base + '/' + path;
    }
    return '/' + path;
  }

  var moduleEl = document.getElementById('module');
  var runBtn = document.getElementById('runScan');
  var dlBtn = document.getElementById('downloadReport');
  var printBtn = document.getElementById('printDashboard');
  var statusEl = document.getElementById('status');
  var cardsEl = document.getElementById('cards');
  var trendEl = document.getElementById('trend');
  var postureSection = document.getElementById('postureSection');
  var overallScoreEl = document.getElementById('overallScore');
  var overallSeverityEl = document.getElementById('overallSeverity');
  var postureCard = document.getElementById('postureCard');
  var dbBackendEl = document.getElementById('dbBackend');
  var findingsModuleLabel = document.getElementById('findingsModuleLabel');
  var apiBaseInput = document.getElementById('apiBaseInput');
  var apiBaseSave = document.getElementById('apiBaseSave');
  var apiBaseHint = document.getElementById('apiBaseHint');

  function parseJsonResponse(res) {
    return res.text().then(function (text) {
      var t = text == null ? '' : String(text).trim();
      if (!t) {
        throw new Error(
          'Empty server response. From the project folder run: php -S localhost:8000 router.php (do not open the HTML file directly).'
        );
      }
      try {
        return JSON.parse(t);
      } catch (err) {
        throw new Error(
          'Server did not return JSON (PHP error or wrong URL). Snippet: ' + t.substring(0, 180)
        );
      }
    });
  }

  function setStatus(msg, isError) {
    statusEl.textContent = msg || '';
    statusEl.classList.toggle('error', !!isError);
  }

  function formatTimestamp(raw) {
    if (!raw) return '-';
    var normalized = String(raw).trim().replace(' ', 'T');
    var d = new Date(normalized);
    if (isNaN(d.getTime())) {
      d = new Date(String(raw));
    }
    if (isNaN(d.getTime())) {
      return String(raw);
    }
    return d.toLocaleString([], {
      year: 'numeric',
      month: 'short',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
    });
  }

  function severityFromScore(score) {
    if (score >= 9.0) return 'Critical';
    if (score >= 7.0) return 'High';
    if (score >= 4.0) return 'Medium';
    return 'Low';
  }

  function maxCvss(list) {
    var m = 0;
    for (var i = 0; i < list.length; i++) {
      var s = Number(list[i].cvss_score);
      if (s > m) m = s;
    }
    return Math.round(m * 10) / 10;
  }

  function sevClass(sev) {
    if (sev === 'Critical' || sev === 'High') return 'sev-high';
    if (sev === 'Medium') return 'sev-medium';
    return 'sev-low';
  }

  function badgeClass(sev) {
    if (sev === 'Critical' || sev === 'High') return 'high';
    if (sev === 'Medium') return 'medium';
    return 'low';
  }

  function setFindingsModuleLabel(text) {
    if (findingsModuleLabel) {
      findingsModuleLabel.textContent = text ? '— ' + text : '';
    }
  }

  function renderCards(vulns) {
    cardsEl.innerHTML = '';
    if (!vulns || !vulns.length) {
      cardsEl.innerHTML = '<p class="hint">No findings for this run.</p>';
      return;
    }
    vulns.forEach(function (v) {
      var card = document.createElement('article');
      card.className = 'card ' + sevClass(v.severity);
      var h = document.createElement('h3');
      h.textContent = v.type;
      var meta = document.createElement('div');
      meta.className = 'meta';
      var badge = document.createElement('span');
      badge.className = 'badge ' + badgeClass(v.severity);
      badge.textContent = v.severity;
      var cvss = document.createElement('span');
      cvss.className = 'cvss';
      cvss.textContent = 'CVSS ' + Number(v.cvss_score).toFixed(1);
      meta.appendChild(badge);
      meta.appendChild(cvss);
      var p = document.createElement('p');
      p.textContent = v.description;
      card.appendChild(h);
      card.appendChild(meta);
      card.appendChild(p);
      cardsEl.appendChild(card);
    });
  }

  function renderPosture(score) {
    var sev = severityFromScore(score);
    overallScoreEl.textContent = score.toFixed(1);
    overallSeverityEl.textContent = 'Rating: ' + sev;
    postureSection.hidden = false;
    postureCard.className = 'posture-card';
    if (sev === 'Critical' || sev === 'High') {
      postureCard.style.background = '#fff5f5';
      postureCard.style.borderColor = '#f3bcbc';
    } else if (sev === 'Medium') {
      postureCard.style.background = '#fffdf3';
      postureCard.style.borderColor = '#e8d59a';
    } else {
      postureCard.style.background = '#f4fbf4';
      postureCard.style.borderColor = '#b7d9b9';
    }
  }

  function renderTrend(history) {
    trendEl.innerHTML = '';
    var slice = history.slice(0, 5);
    if (!slice.length) {
      trendEl.innerHTML = '<p class="hint">No history yet. Run a scan to record results.</p>';
      return;
    }
    slice.forEach(function (row) {
      var item = document.createElement('div');
      item.className = 'trend-item';
      var score = Number(row.overall_score);
      var sev = severityFromScore(score);
      var left = document.createElement('div');
      var ts = formatTimestamp(row.timestamp);
      left.innerHTML =
        '<strong>' +
        row.module +
        '</strong><br/><time>' +
        ts +
        '</time>';
      var mid = document.createElement('span');
      mid.className = 'badge ' + badgeClass(sev);
      mid.textContent = sev;
      var right = document.createElement('strong');
      right.textContent = 'Max CVSS ' + score.toFixed(1);
      item.appendChild(left);
      item.appendChild(mid);
      item.appendChild(right);
      trendEl.appendChild(item);
    });
  }

  function loadHistory() {
    var name = moduleEl.value;
    var url = apiUrl('report/' + encodeURIComponent(name));
    return fetch(url, { headers: { Accept: 'application/json' } }).then(function (res) {
      return parseJsonResponse(res).then(function (body) {
        if (!res.ok) {
          throw new Error((body && body.error) || 'Could not load history');
        }
        return body;
      });
    });
  }

  /**
   * Loads trend + latest stored scan into posture and cards (if any).
   */
  function refreshDashboard() {
    loadHistory()
      .then(function (data) {
        var hist = data.history || [];
        renderTrend(hist);
        if (hist.length) {
          var latest = hist[0];
          setFindingsModuleLabel(moduleEl.value);
          renderPosture(Number(latest.overall_score));
          renderCards(latest.vulnerabilities || []);
          setStatus('Showing latest stored scan for this module.');
        } else {
          setFindingsModuleLabel(moduleEl.value);
          postureSection.hidden = true;
          cardsEl.innerHTML =
            '<p class="hint">No stored scans for this module yet. Run Scan to record results.</p>';
          setStatus('');
        }
      })
      .catch(function (err) {
        trendEl.innerHTML =
          '<p class="hint">Could not load history. Fix the API URL below or run PHP with router.php.</p>';
        postureSection.hidden = true;
        cardsEl.innerHTML = '<p class="hint">Could not load findings.</p>';
        setStatus(
          'Report API failed: ' + (err && err.message ? err.message : 'network or wrong server URL'),
          true
        );
      });
  }

  runBtn.addEventListener('click', function () {
    setStatus('Scanning…');
    runBtn.disabled = true;
    runBtn.setAttribute('aria-busy', 'true');
    var name = moduleEl.value;
    fetch(apiUrl('security-check'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ module: name }),
    })
      .then(function (res) {
        return parseJsonResponse(res).then(function (body) {
          if (!res.ok) throw new Error((body && body.error) || 'Scan failed');
          return body;
        });
      })
      .then(function (data) {
        setFindingsModuleLabel(moduleEl.value);
        var score = maxCvss(data.vulnerabilities || []);
        renderPosture(score);
        renderCards(data.vulnerabilities || []);
        if (data.warning) {
          setStatus('Scan complete. ' + data.warning, true);
        } else {
          setStatus('Scan complete. Results saved.');
        }
        return loadHistory();
      })
      .then(function (data) {
        renderTrend((data && data.history) || []);
      })
      .catch(function (e) {
        setStatus(e.message || 'Error', true);
      })
      .finally(function () {
        runBtn.disabled = false;
        runBtn.removeAttribute('aria-busy');
      });
  });

  dlBtn.addEventListener('click', function () {
    var name = moduleEl.value;
    setStatus('Preparing report…');
    dlBtn.disabled = true;
    fetch(apiUrl('report-export/' + encodeURIComponent(name)))
      .then(function (res) {
        var ct = res.headers.get('Content-Type') || '';
        if (!res.ok) {
          return res.text().then(function (t) {
            throw new Error((t && t.trim()) || 'Download failed');
          });
        }
        if (ct.indexOf('text/html') === -1) {
          return res.text().then(function (t) {
            throw new Error((t && t.trim()) || 'Unexpected response from server');
          });
        }
        return res.blob();
      })
      .then(function (blob) {
        var safe = name.replace(/[^\w\-]+/g, '_');
        var filename = 'security_report_' + safe + '.html';
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
        setStatus('Report downloaded. Open the file and use Print → Save as PDF if needed.');
      })
      .catch(function (e) {
        setStatus(e.message || 'Download failed', true);
      })
      .finally(function () {
        dlBtn.disabled = false;
      });
  });

  if (printBtn) {
    printBtn.addEventListener('click', function () {
      window.print();
    });
  }

  moduleEl.addEventListener('change', function () {
    refreshDashboard();
  });

  function refreshDbLabel() {
    if (!dbBackendEl) return;
    var hUrl = apiUrl('health');
    fetch(hUrl, { headers: { Accept: 'application/json' } })
      .then(function (res) {
        return parseJsonResponse(res);
      })
      .then(function (h) {
        if (h && h.ok && h.db_driver) {
          var storeMsg =
            h.db_driver === 'mysql'
              ? 'Storage: MySQL.'
              : h.db_driver === 'sqlite'
                ? 'Storage: SQLite file (backend/data/security_scans.sqlite).'
                : 'Storage: JSON file (backend/data/scans.json) — no database drivers needed.';
          dbBackendEl.textContent = (apiBase() ? 'API: ' + apiBase() + ' · ' : '') + storeMsg;
        } else if (h && h.error) {
          dbBackendEl.textContent = 'Storage: error — ' + h.error;
        }
      })
      .catch(function (err) {
        dbBackendEl.textContent =
          'Not connected to PHP API. URL tried: ' +
          hUrl +
          ' — ' +
          (err && err.message ? err.message : 'network error') +
          '. Run: php -S localhost:8000 router.php or set API URL in Connection help.';
      });
  }

  function syncApiBaseField() {
    if (apiBaseInput) {
      apiBaseInput.value = apiBase();
    }
    if (apiBaseHint) {
      apiBaseHint.textContent = apiBase()
        ? 'Using API base: ' + apiBase()
        : 'Using same origin (works when you open http://localhost:8000/).';
    }
  }

  if (apiBaseSave && apiBaseInput) {
    apiBaseSave.addEventListener('click', function () {
      var v = apiBaseInput.value.trim().replace(/\/$/, '');
      try {
        if (v) {
          localStorage.setItem(LS_KEY, v);
          window.API_BASE = v;
        } else {
          localStorage.removeItem(LS_KEY);
          window.API_BASE = '';
        }
      } catch (e) {
        window.API_BASE = v;
      }
      syncApiBaseField();
      refreshDbLabel();
      refreshDashboard();
    });
  }

  syncApiBaseField();
  refreshDbLabel();
  refreshDashboard();
})();
