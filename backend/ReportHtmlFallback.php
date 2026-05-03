<?php
declare(strict_types=1);

/**
 * Printable HTML report when ext-xsl is not available.
 *
 * @param array{module: string, vulnerabilities: list<array<string, mixed>>, overall_score: float, generated_at: string} $scan
 */
final class ReportHtmlFallback
{
    public static function render(array $scan): string
    {
        $module = htmlspecialchars($scan['module'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $overall = htmlspecialchars((string) $scan['overall_score'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $at = htmlspecialchars($scan['generated_at'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

        $rows = '';
        foreach ($scan['vulnerabilities'] as $v) {
            $type = htmlspecialchars((string) ($v['type'] ?? ''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
            $desc = htmlspecialchars((string) ($v['description'] ?? ''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
            $cvss = htmlspecialchars((string) ($v['cvss_score'] ?? ''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
            $sev = htmlspecialchars((string) ($v['severity'] ?? ''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
            $cls = 'sev-low';
            if ($sev === 'Critical' || $sev === 'High') {
                $cls = 'sev-high';
            } elseif ($sev === 'Medium') {
                $cls = 'sev-medium';
            }
            $rows .= '<tr class="' . $cls . '"><td>' . $type . '</td><td>' . $sev . '</td><td>' . $cvss . '</td><td>' . $desc . '</td></tr>';
        }

        return '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/><title>Security Assessment — '
            . $module . '</title><style>body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1a1a1a}'
            . 'h1{font-size:22px}table{border-collapse:collapse;width:100%;font-size:13px}'
            . 'th,td{border:1px solid #ccc;padding:8px 10px;vertical-align:top}th{background:#f4f4f4;text-align:left}'
            . '.sev-high{background:#ffe8e0}.sev-medium{background:#fff8e0}.sev-low{background:#e8f7e8}'
            . '.meta{color:#555;font-size:13px}</style></head><body>'
            . '<h1>Automated Security Assessment Report</h1>'
            . '<p class="meta">LibreHealth EHR Workflow — <strong>' . $module . '</strong><br/>Generated: ' . $at . '</p>'
            . '<p><strong>Overall posture (max CVSS):</strong> ' . $overall . '</p>'
            . '<table><thead><tr><th>Type</th><th>Severity</th><th>CVSS</th><th>Description</th></tr></thead>'
            . '<tbody>' . $rows . '</tbody></table>'
            . '<p style="margin-top:28px;font-size:12px;color:#666">Simulated assessment for local demonstration.</p>'
            . '</body></html>';
    }
}
