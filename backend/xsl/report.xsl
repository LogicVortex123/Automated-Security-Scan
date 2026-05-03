<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="html" encoding="UTF-8" indent="yes" doctype-public="-//W3C//DTD HTML 4.01//EN"
    doctype-system="http://www.w3.org/TR/html4/strict.dtd"/>

  <xsl:template match="/scan">
    <html>
      <head>
        <meta charset="utf-8"/>
        <title>Security Assessment — <xsl:value-of select="module"/></title>
        <style type="text/css">
          body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; color: #1a1a1a; }
          h1 { font-size: 22px; margin-bottom: 4px; }
          .meta { color: #555; font-size: 13px; margin-bottom: 20px; }
          .score { font-size: 18px; font-weight: 600; margin: 16px 0; }
          table { border-collapse: collapse; width: 100%; font-size: 13px; }
          th, td { border: 1px solid #ccc; padding: 8px 10px; vertical-align: top; }
          th { background: #f4f4f4; text-align: left; }
          .sev-critical { background: #fde8e8; }
          .sev-high { background: #ffe8e0; }
          .sev-medium { background: #fff8e0; }
          .sev-low { background: #e8f7e8; }
          .footer { margin-top: 28px; font-size: 12px; color: #666; }
        </style>
      </head>
      <body>
        <h1>Automated Security Assessment Report</h1>
        <div class="meta">
          LibreHealth EHR Workflow — <strong><xsl:value-of select="module"/></strong><br/>
          Generated: <xsl:value-of select="generated_at"/>
        </div>
        <div class="score">Overall posture (max CVSS): <xsl:value-of select="overall_score"/></div>
        <table>
          <thead>
            <tr>
              <th>Type</th>
              <th>Severity</th>
              <th>CVSS</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            <xsl:for-each select="vulnerabilities/vulnerability">
              <tr>
                <xsl:attribute name="class">
                  <xsl:choose>
                    <xsl:when test="severity = 'Critical'">sev-critical</xsl:when>
                    <xsl:when test="severity = 'High'">sev-high</xsl:when>
                    <xsl:when test="severity = 'Medium'">sev-medium</xsl:when>
                    <xsl:otherwise>sev-low</xsl:otherwise>
                  </xsl:choose>
                </xsl:attribute>
                <td><xsl:value-of select="type"/></td>
                <td><xsl:value-of select="severity"/></td>
                <td><xsl:value-of select="cvss_score"/></td>
                <td><xsl:value-of select="description"/></td>
              </tr>
            </xsl:for-each>
          </tbody>
        </table>
        <p class="footer">
          Simulated assessment for local demonstration. CVSS values are predefined mock base scores, not live scan output.
        </p>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
