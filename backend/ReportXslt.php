<?php
declare(strict_types=1);

/**
 * Minimal XSLT: transforms scan XML into printable HTML for download.
 */
final class ReportXslt
{
    public static function transform(string $xml): string
    {
        $xslPath = __DIR__ . '/xsl/report.xsl';
        if (!is_readable($xslPath)) {
            throw new RuntimeException('XSL template not found.');
        }

        $doc = new DOMDocument();
        $doc->loadXML($xml);

        $xsl = new DOMDocument();
        $xsl->load($xslPath);

        $proc = new XSLTProcessor();
        $proc->importStylesheet($xsl);
        $out = $proc->transformToXml($doc);
        if ($out === false) {
            throw new RuntimeException('XSLT transformation failed.');
        }
        return $out;
    }

    /**
     * @param array{module: string, vulnerabilities: list<array<string, mixed>>, overall_score: float, generated_at: string} $scan
     */
    public static function scanToXml(array $scan): string
    {
        $module = htmlspecialchars($scan['module'], ENT_XML1 | ENT_QUOTES, 'UTF-8');
        $overall = htmlspecialchars((string) $scan['overall_score'], ENT_XML1 | ENT_QUOTES, 'UTF-8');
        $at = htmlspecialchars($scan['generated_at'], ENT_XML1 | ENT_QUOTES, 'UTF-8');

        $items = '';
        foreach ($scan['vulnerabilities'] as $v) {
            $type = htmlspecialchars((string) $v['type'], ENT_XML1 | ENT_QUOTES, 'UTF-8');
            $desc = htmlspecialchars((string) $v['description'], ENT_XML1 | ENT_QUOTES, 'UTF-8');
            $cvss = htmlspecialchars((string) $v['cvss_score'], ENT_XML1 | ENT_QUOTES, 'UTF-8');
            $sev = htmlspecialchars((string) $v['severity'], ENT_XML1 | ENT_QUOTES, 'UTF-8');
            $items .= "<vulnerability><type>{$type}</type><description>{$desc}</description>"
                . "<cvss_score>{$cvss}</cvss_score><severity>{$sev}</severity></vulnerability>";
        }

        return '<?xml version="1.0" encoding="UTF-8"?>'
            . "<scan><module>{$module}</module><overall_score>{$overall}</overall_score>"
            . "<generated_at>{$at}</generated_at><vulnerabilities>{$items}</vulnerabilities></scan>";
    }
}
