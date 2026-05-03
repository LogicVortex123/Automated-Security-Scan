<?php
declare(strict_types=1);

/**
 * Simulated security scan using predefined CVSS v3.1-style base scores (simplified).
 */
final class SecurityScanner
{
    private const MODULES = [
        'Patient Registration',
        'Lab Results',
        'Billing',
        'Appointment Scheduling',
    ];

    /** Canonical vulnerability definitions with realistic base scores. */
    private const VULN_CATALOG = [
        'SQL Injection' => [
            'type' => 'SQL Injection',
            'description' => 'User-controlled input appears concatenated into SQL queries in the patient search endpoint, enabling classic boolean-based injection against the demographics store.',
            'cvss_score' => 9.3,
        ],
        'Cross-Site Scripting (XSS)' => [
            'type' => 'Cross-Site Scripting (XSS)',
            'description' => 'Output encoding controls are insufficient in user-visible workflow fields, creating a risk of client-side script execution within authenticated sessions.',
            'cvss_score' => 7.4,
        ],
        'Cross-Site Request Forgery (CSRF)' => [
            'type' => 'Cross-Site Request Forgery (CSRF)',
            'description' => 'State-changing endpoints accept cross-origin requests without robust anti-CSRF validation, allowing unauthorized actions via a trusted browser session.',
            'cvss_score' => 6.3,
        ],
        'Weak Authentication' => [
            'type' => 'Weak Authentication',
            'description' => 'Legacy workflow still permits short passwords and does not enforce MFA for privileged roles accessing billing configuration.',
            'cvss_score' => 8.2,
        ],
        'Data Exposure' => [
            'type' => 'Data Exposure',
            'description' => 'Error handling and operational metadata controls may disclose internal identifiers or sensitive context to users beyond intended authorization scope.',
            'cvss_score' => 7.1,
        ],
    ];

    /** Which simulated findings apply per EHR module (realistic mock). */
    private const MODULE_PATTERNS = [
        'Patient Registration' => [
            'SQL Injection',
            'Cross-Site Scripting (XSS)',
            'Weak Authentication',
            'Data Exposure',
        ],
        'Lab Results' => [
            'Cross-Site Scripting (XSS)',
            'Cross-Site Request Forgery (CSRF)',
            'Data Exposure',
        ],
        'Billing' => [
            'SQL Injection',
            'Cross-Site Request Forgery (CSRF)',
            'Weak Authentication',
            'Data Exposure',
        ],
        'Appointment Scheduling' => [
            'Cross-Site Scripting (XSS)',
            'Cross-Site Request Forgery (CSRF)',
            'Weak Authentication',
        ],
    ];

    /**
     * Same vulnerability *type* can appear in several modules; descriptions are tailored per workflow
     * so each module’s scan looks like a different combination.
     *
     * @var array<string, array<string, string>> module => vuln key => description
     */
    private const DESCRIPTION_BY_MODULE = [
        'Patient Registration' => [
            'SQL Injection' => 'The new-patient search and duplicate-check screen builds SQL with unsanitized last-name and DOB fields, exposing the demographics table to boolean-based injection.',
            'Cross-Site Scripting (XSS)' => 'Registration intake fields (for example alias and emergency-contact notes) are rendered in confirmation views without sufficient output encoding, creating stored XSS risk.',
            'Weak Authentication' => 'Self-service pre-registration links rely on short numeric tokens and optional SMS codes only; privileged staff overrides lack step-up MFA.',
            'Data Exposure' => 'Registration quick-view components may disclose full identifiers (for example SSN fragments and prior-visit IDs) to roles that should only receive minimum necessary data.',
        ],
        'Lab Results' => [
            'Cross-Site Scripting (XSS)' => 'Lab result annotations and instrument comments are displayed with insufficient sanitization controls, allowing crafted payloads to execute in clinician browser contexts.',
            'Cross-Site Request Forgery (CSRF)' => 'Result release and addendum workflows rely on authenticated POST requests without strong CSRF token enforcement, enabling request forgery from external origins.',
            'Data Exposure' => 'Laboratory integration diagnostics may persist detailed operational messages that include accession identifiers and result context beyond least-privilege expectations.',
        ],
        'Billing' => [
            'SQL Injection' => 'The claim scrubber’s “reason lookup” concatenates payer code and date range into a raw query, allowing UNION-based reads of charge master rows.',
            'Cross-Site Request Forgery (CSRF)' => 'Billing adjustment and batch payment actions are vulnerable to cross-origin request submission when initiated from an authenticated analyst session.',
            'Weak Authentication' => 'Shared workstation profiles remember billing supervisor passwords; remote clearinghouse SSO bypass still allows local password-only fallback.',
            'Data Exposure' => 'Billing API exception responses may disclose internal claim identifiers, path structures, and processing details to users without operational need.',
        ],
        'Appointment Scheduling' => [
            'Cross-Site Scripting (XSS)' => 'Scheduling notes and imported roster labels are rendered in calendar views without comprehensive sanitization, introducing persistent XSS exposure.',
            'Cross-Site Request Forgery (CSRF)' => 'Appointment move/cancel operations can be submitted as forged cross-origin POST requests due to missing anti-CSRF controls in calendar actions.',
            'Weak Authentication' => 'Front-desk kiosks stay signed in as generic scheduling users overnight; quick-unlock PIN is four digits with no lockout policy.',
        ],
    ];

    public static function validModules(): array
    {
        return self::MODULES;
    }

    public static function isValidModule(string $name): bool
    {
        return in_array($name, self::MODULES, true);
    }

    /**
     * @return array{module: string, vulnerabilities: list<array{type: string, description: string, cvss_score: float, severity: string}>}
     */
    public static function scan(string $module): array
    {
        if (!self::isValidModule($module)) {
            throw new InvalidArgumentException('Unknown module name.');
        }

        $keys = self::MODULE_PATTERNS[$module] ?? [];
        $vulns = [];
        $descMap = self::DESCRIPTION_BY_MODULE[$module] ?? [];
        foreach ($keys as $key) {
            $row = self::VULN_CATALOG[$key];
            $score = (float) $row['cvss_score'];
            $description = $descMap[$key] ?? $row['description'];
            $vulns[] = [
                'type' => $row['type'],
                'description' => $description,
                'cvss_score' => $score,
                'severity' => self::severityFromCvss($score),
            ];
        }

        return [
            'module' => $module,
            'vulnerabilities' => $vulns,
        ];
    }

    public static function severityFromCvss(float $score): string
    {
        if ($score >= 9.0) {
            return 'Critical';
        }
        if ($score >= 7.0) {
            return 'High';
        }
        if ($score >= 4.0) {
            return 'Medium';
        }
        if ($score >= 0.1) {
            return 'Low';
        }
        return 'Low';
    }

    /**
     * Overall posture: maximum CVSS among findings (worst-case for the workflow).
     */
    public static function overallScore(array $vulnerabilities): float
    {
        $max = 0.0;
        foreach ($vulnerabilities as $v) {
            $max = max($max, (float) $v['cvss_score']);
        }
        return round($max, 1);
    }
}
