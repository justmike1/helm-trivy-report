<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background-color: #f8f9fa;
            color: #212529;
            font-size: 13px;
            line-height: 1.4;
            padding: 16px;
        }
        h1 {
            text-align: center;
            font-size: 1.4em;
            font-weight: 700;
            margin: 12px 0 16px;
            color: #1a1a2e;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
            table-layout: auto;
        }
        th, td {
            border: 1px solid #dee2e6;
            padding: 6px 10px;
            text-align: left;
            vertical-align: top;
            word-wrap: break-word;
            overflow-wrap: break-word;
        }
        /* Group header — image name */
        .group-header th {
            background: linear-gradient(135deg, #1a1a2e, #16213e);
            color: #ffffff;
            font-size: 1.1em;
            font-weight: 600;
            padding: 10px 12px;
            text-align: left;
            letter-spacing: 0.02em;
        }
        /* Column sub-header */
        .sub-header th {
            background-color: #e9ecef;
            color: #495057;
            font-size: 0.85em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            padding: 6px 10px;
            white-space: nowrap;
        }
        /* Severity badge */
        .severity {
            display: inline-block;
            min-width: 68px;
            padding: 2px 8px;
            border-radius: 3px;
            font-weight: 600;
            font-size: 0.82em;
            text-align: center;
            color: #fff;
            letter-spacing: 0.03em;
        }
        .severity-CRITICAL .severity { background-color: #dc3545; }
        .severity-HIGH .severity     { background-color: #fd7e14; }
        .severity-MEDIUM .severity   { background-color: #ffc107; color: #212529; }
        .severity-LOW .severity      { background-color: #28a745; }
        .severity-UNKNOWN .severity  { background-color: #6c757d; }
        /* Row tint */
        .severity-CRITICAL { background-color: #dc354510; }
        .severity-HIGH     { background-color: #fd7e1410; }
        .severity-MEDIUM   { background-color: #ffc10710; }
        .severity-LOW      { background-color: #28a74510; }
        .severity-UNKNOWN  { background-color: #6c757d10; }
        /* Row hover */
        tbody tr:hover {
            background-color: #f1f3f5;
        }
        /* Package name */
        .pkg-name {
            font-weight: 600;
            color: #1a1a2e;
        }
        /* Version columns */
        .pkg-version, td:nth-child(5) {
            font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
            font-size: 0.9em;
        }
        /* No-vulnerability row */
        tr th[colspan] {
            text-align: center;
        }
        /* Links column */
        td.links {
            max-width: 260px;
            font-size: 0.82em;
        }
        td.links a {
            display: block;
            color: #0366d6;
            text-decoration: none;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            margin: 1px 0;
        }
        td.links a:hover {
            text-decoration: underline;
        }
        td.links[data-more-links="off"] a:nth-child(n+4):not(.toggle-more-links) {
            display: none;
        }
        a.toggle-more-links {
            color: #6c757d;
            font-style: italic;
            cursor: pointer;
            display: block;
            margin-top: 2px;
        }
        /* Misconfiguration message */
        td.link {
            font-size: 0.88em;
            line-height: 1.35;
        }
        td.link a {
            color: #0366d6;
            word-break: break-all;
        }
        hr {
            border: none;
            border-top: 1px solid #dee2e6;
            margin: 8px 0;
        }

        @media print {
            body {
                padding: 0;
                font-size: 9pt;
            }
            .group-header th {
                background: #1a1a2e !important;
                -webkit-print-color-adjust: exact;
                print-color-adjust: exact;
            }
            .sub-header th {
                background-color: #e9ecef !important;
                -webkit-print-color-adjust: exact;
                print-color-adjust: exact;
            }
            .severity {
                -webkit-print-color-adjust: exact;
                print-color-adjust: exact;
            }
            tr:hover {
                background-color: transparent;
            }
            table {
                page-break-inside: auto;
            }
            tr {
                page-break-inside: avoid;
                page-break-after: auto;
            }
        }
    </style>
    <title>{{- escapeXML ( index . 0 ).Target }} - Trivy Report</title>
{{/* LINKS_ONLY */}}
    <script>
      window.onload = function() {
        document.querySelectorAll('td.links').forEach(function(linkCell) {
          var links = [].concat.apply([], linkCell.querySelectorAll('a'));
          [].sort.apply(links, function(a, b) {
            return a.href > b.href ? 1 : -1;
          });
          links.forEach(function(link, idx) {
            if (links.length > 3 && 3 === idx) {
              var toggleLink = document.createElement('a');
              toggleLink.innerText = "Toggle more links";
              toggleLink.href = "#toggleMore";
              toggleLink.setAttribute("class", "toggle-more-links");
              linkCell.appendChild(toggleLink);
            }
            linkCell.appendChild(link);
          });
        });
        document.querySelectorAll('a.toggle-more-links').forEach(function(toggleLink) {
          toggleLink.onclick = function() {
            var expanded = toggleLink.parentElement.getAttribute("data-more-links");
            toggleLink.parentElement.setAttribute("data-more-links", "on" === expanded ? "off" : "on");
            return false;
          };
        });
      };
    </script>
{{/* END_LINKS_ONLY */}}
  </head>
<body>
    {{- if . }}
    <h1>{{- escapeXML ( index . 0 ).Target }}</h1>
    <table>
    {{- range . }}
      <tr class="group-header"><th colspan="__TOTAL_COLS__">{{ .Type | toString | escapeXML }}</th></tr>
      {{- if (eq (len .Vulnerabilities) 0) }}
      <tr><th colspan="__TOTAL_COLS__">No Vulnerabilities found</th></tr>
      {{- else }}
      <tr class="sub-header">
        <th>Package</th>
        <th>Vulnerability ID</th>
        <th>Severity</th>
        <th>Installed Version</th>
        <th>Fixed Version</th>
{{/* LINKS_ONLY */}}
        <th>Links</th>
{{/* END_LINKS_ONLY */}}
      </tr>
        {{- range .Vulnerabilities }}
      <tr class="severity-{{ escapeXML .Vulnerability.Severity }}">
        <td class="pkg-name">{{ escapeXML .PkgName }}</td>
        <td>{{ escapeXML .VulnerabilityID }}</td>
        <td class="severity">{{ escapeXML .Vulnerability.Severity }}</td>
        <td class="pkg-version">{{ escapeXML .InstalledVersion }}</td>
        <td>{{ escapeXML .FixedVersion }}</td>
{{/* LINKS_ONLY */}}
        <td class="links" data-more-links="off">
          {{- range .Vulnerability.References }}
          <a href={{ escapeXML . | printf "%q" }}>{{ escapeXML . }}</a>
          {{- end }}
        </td>
{{/* END_LINKS_ONLY */}}
      </tr>
        {{- end }}
      {{- end }}
      {{- if (eq (len .Misconfigurations ) 0) }}
      <tr><th colspan="__TOTAL_COLS__">No Misconfigurations found</th></tr>
      {{- else }}
      <tr class="sub-header">
        <th>Type</th>
        <th>Misconf ID</th>
        <th>Check</th>
        <th>Severity</th>
        <th>Message</th>
      </tr>
        {{- range .Misconfigurations }}
      <tr class="severity-{{ escapeXML .Severity }}">
        <td class="misconf-type">{{ .Type | toString | escapeXML }}</td>
        <td>{{ escapeXML .ID }}</td>
        <td class="misconf-check">{{ escapeXML .Title }}</td>
        <td class="severity">{{ escapeXML .Severity }}</td>
        <td class="link" data-more-links="off" style="white-space:normal;">
          {{ escapeXML .Message }}
{{/* LINKS_ONLY */}}
          <br>
            <a href={{ escapeXML .PrimaryURL | printf "%q" }}>{{ escapeXML .PrimaryURL }}</a>
          </br>
{{/* END_LINKS_ONLY */}}
        </td>
      </tr>
        {{- end }}
      {{- end }}
    {{- end }}
    </table>
    {{- else }}
    <h1>Trivy Returned Empty Report</h1>
    {{- end }}
    <hr>
</body>
</html>
