import * as fs from 'fs';
import * as path from 'path';

export interface Vulnerability {
  id: string;
  title: string;
  type: string;
  cwe: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  cvssScore: number;
  cvssVector: string;
  description: string;
  impact: string;
  exploitability: string;
  affectedEndpoints: string[];
  evidence: {
    request?: string;
    response?: string;
    screenshot?: string;
    payload?: string;
  };
  remediation: {
    immediate: string;
    longTerm: string;
    code?: string;
  };
  references: string[];
}

export interface AssessmentReport {
  metadata: {
    target: string;
    timestamp: string;
    assessmentType: string;
    methodology: string;
    tools: string[];
    duration: string;
    tester: string;
  };
  executiveSummary: {
    overallRisk: string;
    totalVulnerabilities: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    businessImpact: string;
    recommendation: string;
  };
  vulnerabilities: Vulnerability[];
  appendices: {
    methodology: string;
    toolsUsed: string;
    references: string[];
  };
}

export class VulnerabilityReportGenerator {
  private vulnerabilities: Vulnerability[] = [];
  private metadata: any = {};

  constructor(target: string) {
    this.metadata = {
      target,
      timestamp: new Date().toISOString(),
      assessmentType: 'Comprehensive Security Assessment',
      methodology: 'OWASP Testing Guide v4.0',
      tools: ['Custom Exploits', 'SQLMap', 'OWASP ZAP', 'Burp Suite'],
      duration: 'Automated',
      tester: 'Automated Security Framework'
    };
  }

  addVulnerability(vulnerability: Vulnerability): void {
    this.vulnerabilities.push(vulnerability);
  }

  calculateCVSSScore(vulnerability: Partial<Vulnerability>): number {
    // Simplified CVSS calculation based on vulnerability type
    const cvssScores: { [key: string]: number } = {
      'SQL Injection': 9.8,
      'Cross-Site Scripting': 6.1,
      'IDOR': 8.1,
      'SSRF': 8.6,
      'Session Management': 7.5,
      'Authentication Bypass': 9.1,
      'Information Disclosure': 5.3,
      'Missing Security Headers': 3.7
    };

    return cvssScores[vulnerability.title || ''] || 5.0;
  }

  generateExecutiveSummary(): any {
    const criticalCount = this.vulnerabilities.filter(v => v.severity === 'CRITICAL').length;
    const highCount = this.vulnerabilities.filter(v => v.severity === 'HIGH').length;
    const mediumCount = this.vulnerabilities.filter(v => v.severity === 'MEDIUM').length;
    const lowCount = this.vulnerabilities.filter(v => v.severity === 'LOW').length;

    let overallRisk = 'LOW';
    if (criticalCount > 0) overallRisk = 'CRITICAL';
    else if (highCount > 0) overallRisk = 'HIGH';
    else if (mediumCount > 0) overallRisk = 'MEDIUM';

    return {
      overallRisk,
      totalVulnerabilities: this.vulnerabilities.length,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      businessImpact: this.getBusinessImpact(overallRisk),
      recommendation: this.getRecommendation(overallRisk)
    };
  }

  private getBusinessImpact(riskLevel: string): string {
    const impacts = {
      'CRITICAL': 'Complete system compromise possible, immediate business disruption likely',
      'HIGH': 'Significant security breach possible, potential data loss and reputation damage',
      'MEDIUM': 'Moderate security risks present, potential for limited data exposure',
      'LOW': 'Minor security issues identified, minimal business impact expected'
    };
    return impacts[riskLevel] || 'Security assessment completed';
  }

  private getRecommendation(riskLevel: string): string {
    const recommendations = {
      'CRITICAL': 'Immediate remediation required before production deployment',
      'HIGH': 'High priority remediation recommended within 30 days',
      'MEDIUM': 'Medium priority remediation recommended within 90 days',
      'LOW': 'Low priority remediation can be scheduled in next maintenance cycle'
    };
    return recommendations[riskLevel] || 'Continue regular security assessments';
  }

  generateJSONReport(): AssessmentReport {
    return {
      metadata: this.metadata,
      executiveSummary: this.generateExecutiveSummary(),
      vulnerabilities: this.vulnerabilities,
      appendices: {
        methodology: 'OWASP Testing Guide v4.0 methodology was followed',
        toolsUsed: 'Combination of automated tools and manual testing',
        references: [
          'https://owasp.org/www-project-top-ten/',
          'https://cwe.mitre.org/',
          'https://nvd.nist.gov/vuln-metrics/cvss'
        ]
      }
    };
  }

  generateHTMLReport(): string {
    const report = this.generateJSONReport();
    
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f8f9fa;
            line-height: 1.6;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }
        .header {
            background: linear-gradient(135deg, #2c3e50, #34495e);
            color: white;
            padding: 40px;
            text-align: center;
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
        }
        .header p {
            margin: 10px 0 0 0;
            opacity: 0.9;
        }
        .executive-summary {
            background: #ecf0f1;
            padding: 30px;
            margin: 0;
        }
        .risk-critical { color: #e74c3c; font-weight: bold; }
        .risk-high { color: #f39c12; font-weight: bold; }
        .risk-medium { color: #f1c40f; font-weight: bold; }
        .risk-low { color: #27ae60; font-weight: bold; }
        
        .vulnerability {
            margin: 30px;
            padding: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .vulnerability.critical {
            border-left: 6px solid #e74c3c;
            background: #fdf2f2;
        }
        .vulnerability.high {
            border-left: 6px solid #f39c12;
            background: #fef9e7;
        }
        .vulnerability.medium {
            border-left: 6px solid #f1c40f;
            background: #fffbf0;
        }
        .vulnerability.low {
            border-left: 6px solid #27ae60;
            background: #f0fff4;
        }
        
        .cvss-score {
            font-size: 28px;
            font-weight: bold;
            display: inline-block;
            padding: 10px 15px;
            border-radius: 5px;
            color: white;
            background: #e74c3c;
        }
        
        .evidence {
            background: #2c3e50;
            color: #ecf0f1;
            padding: 20px;
            margin: 15px 0;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            overflow-x: auto;
        }
        
        .remediation {
            background: #d4edda;
            border: 1px solid #c3e6cb;
            padding: 20px;
            margin: 15px 0;
            border-radius: 5px;
        }
        
        .stats {
            display: flex;
            justify-content: space-around;
            margin: 20px 0;
        }
        
        .stat {
            text-align: center;
            padding: 20px;
        }
        
        .stat-number {
            font-size: 2em;
            font-weight: bold;
            display: block;
        }
        
        .methodology {
            background: #f8f9fa;
            padding: 30px;
            margin: 30px 0;
        }
        
        .footer {
            background: #2c3e50;
            color: white;
            padding: 20px;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Assessment Report</h1>
            <p><strong>Target:</strong> ${report.metadata.target}</p>
            <p><strong>Assessment Date:</strong> ${new Date(report.metadata.timestamp).toLocaleDateString()}</p>
            <p><strong>Methodology:</strong> ${report.metadata.methodology}</p>
        </div>
        
        <div class="executive-summary">
            <h2>Executive Summary</h2>
            <p><strong>Overall Risk Level:</strong> 
                <span class="risk-${report.executiveSummary.overallRisk.toLowerCase()}">
                    ${report.executiveSummary.overallRisk}
                </span>
            </p>
            
            <div class="stats">
                <div class="stat">
                    <span class="stat-number risk-critical">${report.executiveSummary.criticalCount}</span>
                    <span>Critical</span>
                </div>
                <div class="stat">
                    <span class="stat-number risk-high">${report.executiveSummary.highCount}</span>
                    <span>High</span>
                </div>
                <div class="stat">
                    <span class="stat-number risk-medium">${report.executiveSummary.mediumCount}</span>
                    <span>Medium</span>
                </div>
                <div class="stat">
                    <span class="stat-number risk-low">${report.executiveSummary.lowCount}</span>
                    <span>Low</span>
                </div>
            </div>
            
            <p><strong>Business Impact:</strong> ${report.executiveSummary.businessImpact}</p>
            <p><strong>Recommendation:</strong> ${report.executiveSummary.recommendation}</p>
        </div>
        
        ${report.vulnerabilities.map((vuln, index) => `
        <div class="vulnerability ${vuln.severity.toLowerCase()}">
            <h3>${vuln.id}: ${vuln.title}</h3>
            <div style="margin: 15px 0;">
                <span class="cvss-score">${vuln.cvssScore}</span>
                <span style="margin-left: 15px;">
                    <strong>Severity:</strong> ${vuln.severity} | 
                    <strong>Type:</strong> ${vuln.cwe}
                </span>
            </div>
            
            <p><strong>Description:</strong> ${vuln.description}</p>
            <p><strong>Impact:</strong> ${vuln.impact}</p>
            <p><strong>Exploitability:</strong> ${vuln.exploitability}</p>
            <p><strong>Affected Endpoints:</strong> ${vuln.affectedEndpoints.join(', ')}</p>
            
            ${vuln.evidence.request ? `
            <h4>Evidence</h4>
            <div class="evidence">
                <strong>Request:</strong><br>
                ${vuln.evidence.request}<br><br>
                <strong>Response:</strong><br>
                ${vuln.evidence.response || 'See attached screenshot'}
            </div>
            ` : ''}
            
            <h4>Remediation</h4>
            <div class="remediation">
                <p><strong>Immediate Action:</strong> ${vuln.remediation.immediate}</p>
                <p><strong>Long-term Solution:</strong> ${vuln.remediation.longTerm}</p>
                ${vuln.remediation.code ? `
                <p><strong>Code Example:</strong></p>
                <div class="evidence">${vuln.remediation.code}</div>
                ` : ''}
            </div>
        </div>
        `).join('')}
        
        <div class="methodology">
            <h2>Assessment Methodology</h2>
            <p>${report.appendices.methodology}</p>
            <p><strong>Tools Used:</strong> ${report.metadata.tools.join(', ')}</p>
            <p><strong>Duration:</strong> ${report.metadata.duration}</p>
        </div>
        
        <div class="footer">
            <p>Report generated by ${report.metadata.tester}</p>
            <p>Generated on ${new Date().toLocaleString()}</p>
        </div>
    </div>
</body>
</html>`;
  }

  saveReports(outputDir: string): { json: string; html: string } {
    fs.mkdirSync(outputDir, { recursive: true });
    
    const jsonReport = this.generateJSONReport();
    const htmlReport = this.generateHTMLReport();
    
    const jsonPath = path.join(outputDir, 'vulnerability-assessment.json');
    const htmlPath = path.join(outputDir, 'vulnerability-assessment.html');
    
    fs.writeFileSync(jsonPath, JSON.stringify(jsonReport, null, 2));
    fs.writeFileSync(htmlPath, htmlReport);
    
    return { json: jsonPath, html: htmlPath };
  }
}