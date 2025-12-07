"""
PDF Report Generator Module
Generates professional PDF security assessment reports
"""

from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.lib.colors import HexColor
from datetime import datetime
import os


class PDFReportGenerator:
    """
    Generates comprehensive PDF security assessment reports
    from parsed scan results
    """
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """
        Create custom paragraph styles for the report
        """
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a237e'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        # Heading style
        self.styles.add(ParagraphStyle(
            name='CustomHeading',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#283593'),
            spaceAfter=12,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        ))
        
        # Subheading style
        self.styles.add(ParagraphStyle(
            name='CustomSubHeading',
            parent=self.styles['Heading3'],
            fontSize=12,
            textColor=colors.HexColor('#3949ab'),
            spaceAfter=6,
            spaceBefore=6,
            fontName='Helvetica-Bold'
        ))
        
        # Security context style (italic)
        self.styles.add(ParagraphStyle(
            name='SecurityContext',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#424242'),
            fontName='Helvetica-Oblique',
            leftIndent=20,
            spaceAfter=10
        ))
        
        # Warning style
        self.styles.add(ParagraphStyle(
            name='Warning',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.red,
            leftIndent=20
        ))
    
    def generate_report(self, parsed_results, summary, output_path):
        """
        Generate a comprehensive PDF report
        
        Args:
            parsed_results (list): List of parsed scan results
            summary (dict): Summary statistics
            output_path (str): Path to save the PDF
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Create PDF document
            doc = SimpleDocTemplate(
                output_path,
                pagesize=letter,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=18
            )
            
            # Container for the 'Flowable' objects
            elements = []
            
            # Build report sections
            elements.extend(self._build_cover_page(summary))
            elements.append(PageBreak())
            
            elements.extend(self._build_executive_summary(summary))
            elements.append(PageBreak())
            
            elements.extend(self._build_methodology_section())
            elements.append(PageBreak())
            
            elements.extend(self._build_detailed_findings(parsed_results))
            elements.append(PageBreak())
            
            elements.extend(self._build_conclusions(summary))
            
            # Build PDF
            doc.build(elements)
            
            print(f"\n[✓] PDF report generated successfully: {output_path}")
            return True
            
        except Exception as e:
            print(f"\n[✗] Error generating PDF report: {str(e)}")
            return False
    
    def _build_cover_page(self, summary):
        """
        Build the cover page
        """
        elements = []
        
        # Title
        elements.append(Spacer(1, 2*inch))
        title = Paragraph("Network Security Assessment Report", self.styles['CustomTitle'])
        elements.append(title)
        elements.append(Spacer(1, 0.5*inch))
        
        # Subtitle
        subtitle = Paragraph(
            "Educational Security Analysis",
            self.styles['Heading2']
        )
        elements.append(subtitle)
        elements.append(Spacer(1, 1*inch))
        
        # Report info
        report_date = datetime.now().strftime("%B %d, %Y")
        report_info = [
            f"<b>Report Date:</b> {report_date}",
            f"<b>Total Targets:</b> {len(summary.get('targets_scanned', []))}",
            f"<b>Total Scans:</b> {summary.get('total_scans', 0)}",
            f"<b>Assessment Type:</b> Network Reconnaissance & Port Analysis"
        ]
        
        for info in report_info:
            elements.append(Paragraph(info, self.styles['Normal']))
            elements.append(Spacer(1, 0.1*inch))
        
        # Disclaimer
        elements.append(Spacer(1, 1*inch))
        disclaimer = Paragraph(
            "<b>DISCLAIMER:</b> This report was generated for educational purposes only "
            "as part of an Introduction to Security course. All scanning activities were "
            "conducted with proper authorization and in accordance with applicable laws and policies.",
            self.styles['Normal']
        )
        elements.append(disclaimer)
        
        return elements
    
    def _build_executive_summary(self, summary):
        """
        Build executive summary section
        """
        elements = []
        
        elements.append(Paragraph("Executive Summary", self.styles['CustomHeading']))
        elements.append(Spacer(1, 0.2*inch))
        
        # Summary text
        summary_text = (
            f"This report presents the findings of a network security assessment conducted on "
            f"{len(summary.get('targets_scanned', []))} target(s). The assessment utilized "
            f"various reconnaissance techniques covered in the Introduction to Security curriculum "
            f"to identify active hosts, open ports, and running services."
        )
        elements.append(Paragraph(summary_text, self.styles['Normal']))
        elements.append(Spacer(1, 0.3*inch))
        
        # Statistics table
        elements.append(Paragraph("Assessment Statistics", self.styles['CustomSubHeading']))
        
        stats_data = [
            ['Metric', 'Count'],
            ['Total Scans Performed', str(summary.get('total_scans', 0))],
            ['Successful Scans', str(summary.get('successful_scans', 0))],
            ['Failed Scans', str(summary.get('failed_scans', 0))],
            ['Hosts Up', str(summary.get('hosts_up', 0))],
            ['Hosts Down', str(summary.get('hosts_down', 0))],
            ['Total Open Ports Found', str(summary.get('total_open_ports', 0))],
            ['Unique Services Detected', str(len(summary.get('unique_services', [])))]
        ]
        
        stats_table = Table(stats_data, colWidths=[4*inch, 2*inch])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3949ab')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.whitesmoke, colors.lightgrey])
        ]))
        
        elements.append(stats_table)
        elements.append(Spacer(1, 0.3*inch))
        
        # Services found
        if summary.get('unique_services'):
            elements.append(Paragraph("Services Identified", self.styles['CustomSubHeading']))
            services_text = ", ".join(summary.get('unique_services', []))
            elements.append(Paragraph(services_text, self.styles['Normal']))
        
        return elements
    
    def _build_methodology_section(self):
        """
        Build methodology section explaining scan types
        """
        elements = []
        
        elements.append(Paragraph("Assessment Methodology", self.styles['CustomHeading']))
        elements.append(Spacer(1, 0.2*inch))
        
        intro = (
            "This assessment employed multiple reconnaissance techniques to gather information "
            "about the target network. All techniques used are standard practices in the field "
            "of information security and are covered in introductory security courses. Below is "
            "a description of each technique and its purpose in security assessments."
        )
        elements.append(Paragraph(intro, self.styles['Normal']))
        elements.append(Spacer(1, 0.2*inch))
        
        # Scan techniques
        techniques = [
            {
                'name': 'Host Discovery (Ping Scan)',
                'command': 'nmap -sn [target]',
                'purpose': 'Identifies which hosts are active on the network without performing port scanning. '
                          'This is the first step in network reconnaissance, helping to map the attack surface.',
                'security_relevance': 'An attacker uses this to identify potential targets before launching more '
                                    'aggressive scans. Essential for efficient reconnaissance.'
            },
            {
                'name': 'TCP Connect Scan',
                'command': 'nmap -sT [target]',
                'purpose': 'Establishes full TCP connections to determine which ports are open. This is the most '
                          'basic form of port scanning and does not require elevated privileges.',
                'security_relevance': 'While more detectable, this scan provides reliable information about '
                                    'accessible services. Defenders can easily detect and log these connection attempts.'
            },
            {
                'name': 'TCP SYN Scan (Stealth Scan)',
                'command': 'nmap -sS [target]',
                'purpose': 'Sends TCP SYN packets without completing the three-way handshake, making it less likely '
                          'to be logged by the target system.',
                'security_relevance': 'Considered "stealthy" because it doesn\'t establish full connections. '
                                    'Commonly used by both security professionals and attackers for reconnaissance.'
            },
            {
                'name': 'Service Version Detection',
                'command': 'nmap -sV [target]',
                'purpose': 'Probes open ports to determine the exact service and version information, which is '
                          'critical for vulnerability assessment.',
                'security_relevance': 'Enables identification of outdated or vulnerable software versions. This is '
                                    'a key step in the vulnerability assessment process.'
            },
            {
                'name': 'Top Ports Scan',
                'command': 'nmap --top-ports 20 [target]',
                'purpose': 'Quickly scans the most commonly used ports, providing rapid results for initial assessment.',
                'security_relevance': 'Efficient for quick reconnaissance when time or resources are limited. '
                                    'Focuses on ports most likely to be exploitable.'
            }
        ]
        
        for technique in techniques:
            elements.append(Paragraph(technique['name'], self.styles['CustomSubHeading']))
            elements.append(Paragraph(f"<b>Command:</b> <font name='Courier'>{technique['command']}</font>", 
                                    self.styles['Normal']))
            elements.append(Spacer(1, 0.05*inch))
            elements.append(Paragraph(f"<b>Purpose:</b> {technique['purpose']}", self.styles['Normal']))
            elements.append(Spacer(1, 0.05*inch))
            elements.append(Paragraph(f"<b>Security Relevance:</b> {technique['security_relevance']}", 
                                    self.styles['SecurityContext']))
            elements.append(Spacer(1, 0.15*inch))
        
        return elements
    
    def _build_detailed_findings(self, parsed_results):
        """
        Build detailed findings section
        """
        elements = []
        
        elements.append(Paragraph("Detailed Findings", self.styles['CustomHeading']))
        elements.append(Spacer(1, 0.2*inch))
        
        # Group results by target
        targets_dict = {}
        for result in parsed_results:
            target = result.get('target', 'Unknown')
            if target not in targets_dict:
                targets_dict[target] = []
            targets_dict[target].append(result)
        
        # Build findings for each target
        for target, results in targets_dict.items():
            elements.append(Paragraph(f"Target: {target}", self.styles['CustomSubHeading']))
            elements.append(Spacer(1, 0.1*inch))
            
            # Host status
            host_status = results[0].get('host_status', 'unknown').upper()
            status_color = 'green' if host_status == 'UP' else 'red'
            elements.append(Paragraph(
                f"<b>Host Status:</b> <font color='{status_color}'>{host_status}</font>",
                self.styles['Normal']
            ))
            elements.append(Spacer(1, 0.1*inch))
            
            # Scans performed
            elements.append(Paragraph("<b>Scans Performed:</b>", self.styles['Normal']))
            for result in results:
                scan_name = result.get('scan_name', 'Unknown')
                timestamp = result.get('timestamp', 'Unknown')
                elements.append(Paragraph(
                    f"• {scan_name} at {timestamp}",
                    self.styles['Normal']
                ))
                
                # Security context
                if result.get('security_context'):
                    elements.append(Paragraph(
                        f"<i>Security Purpose: {result['security_context']}</i>",
                        self.styles['SecurityContext']
                    ))
            
            elements.append(Spacer(1, 0.1*inch))
            
            # Collect all open ports from all scans
            all_ports = []
            for result in results:
                for port in result.get('ports', []):
                    if port.get('state') == 'open':
                        all_ports.append(port)
            
            # Display open ports
            if all_ports:
                elements.append(Paragraph("<b>Open Ports Discovered:</b>", self.styles['Normal']))
                
                # Create table for ports
                port_data = [['Port', 'Protocol', 'Service', 'Version/Details']]
                for port in all_ports:
                    port_data.append([
                        port.get('port', 'N/A'),
                        port.get('protocol', 'N/A'),
                        port.get('service', 'N/A'),
                        port.get('version', '-')
                    ])
                
                port_table = Table(port_data, colWidths=[1*inch, 1*inch, 1.5*inch, 3*inch])
                port_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3949ab')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.whitesmoke, colors.lightgrey])
                ]))
                
                elements.append(port_table)
            else:
                elements.append(Paragraph("No open ports discovered.", self.styles['Normal']))
            
            elements.append(Spacer(1, 0.2*inch))
            
            # Security implications
            if all_ports:
                elements.append(Paragraph("<b>Security Implications:</b>", self.styles['Normal']))
                implications_text = (
                    f"This target has {len(all_ports)} open port(s), indicating active services that could "
                    "potentially be exploited if vulnerabilities exist. Each open port represents a potential "
                    "attack vector and should be evaluated for security hardening."
                )
                elements.append(Paragraph(implications_text, self.styles['Normal']))
            
            elements.append(Spacer(1, 0.3*inch))
        
        return elements
    
    def _build_conclusions(self, summary):
        """
        Build conclusions and recommendations
        """
        elements = []
        
        elements.append(Paragraph("Conclusions and Learning Outcomes", self.styles['CustomHeading']))
        elements.append(Spacer(1, 0.2*inch))
        
        # Findings summary
        elements.append(Paragraph("Summary of Findings", self.styles['CustomSubHeading']))
        findings_text = (
            f"This assessment successfully identified {summary.get('hosts_up', 0)} active host(s) "
            f"and discovered {summary.get('total_open_ports', 0)} open port(s) across all targets. "
        )
        
        if summary.get('unique_services'):
            findings_text += (
                f"A total of {len(summary.get('unique_services', []))} unique service type(s) were identified, "
                f"including: {', '.join(summary.get('unique_services', []))}. "
            )
        
        findings_text += (
            "These findings demonstrate the effectiveness of systematic network reconnaissance in "
            "identifying potential security exposures."
        )
        
        elements.append(Paragraph(findings_text, self.styles['Normal']))
        elements.append(Spacer(1, 0.2*inch))
        
        # Educational takeaways
        elements.append(Paragraph("Educational Takeaways", self.styles['CustomSubHeading']))
        
        takeaways = [
            "<b>Reconnaissance is Critical:</b> Understanding the network landscape is the first step in both "
            "offensive and defensive security operations.",
            
            "<b>Layered Approach:</b> Different scan types provide different types of information. Host discovery, "
            "port scanning, and service detection work together to build a complete picture.",
            
            "<b>Stealth vs. Accuracy:</b> Different scan techniques offer trade-offs between stealth and accuracy. "
            "SYN scans are stealthier but require elevated privileges.",
            
            "<b>Service Enumeration:</b> Identifying specific software versions is crucial for vulnerability "
            "assessment and exploit development.",
            
            "<b>Legal and Ethical Considerations:</b> Network scanning should only be performed with explicit "
            "authorization. Unauthorized scanning is illegal in most jurisdictions.",
            
            "<b>Defense Perspective:</b> Understanding these reconnaissance techniques helps defenders implement "
            "better detection and prevention mechanisms."
        ]
        
        for takeaway in takeaways:
            elements.append(Paragraph(f"• {takeaway}", self.styles['Normal']))
            elements.append(Spacer(1, 0.1*inch))
        
        elements.append(Spacer(1, 0.2*inch))
        
        # Recommendations
        elements.append(Paragraph("Security Recommendations", self.styles['CustomSubHeading']))
        
        recommendations = [
            "Minimize exposed services and close unnecessary ports",
            "Implement network segmentation to limit reconnaissance scope",
            "Deploy intrusion detection systems (IDS) to detect scanning activities",
            "Regularly update and patch all network services",
            "Use firewalls to filter unauthorized connection attempts",
            "Conduct regular security assessments to identify exposures before attackers do"
        ]
        
        for rec in recommendations:
            elements.append(Paragraph(f"• {rec}", self.styles['Normal']))
            elements.append(Spacer(1, 0.05*inch))
        
        return elements


# Example usage and testing
if __name__ == "__main__":
    # Test data
    sample_summary = {
        'total_scans': 4,
        'successful_scans': 4,
        'failed_scans': 0,
        'hosts_up': 1,
        'hosts_down': 0,
        'total_open_ports': 3,
        'unique_services': ['ssh', 'http', 'https'],
        'targets_scanned': ['scanme.nmap.org']
    }
    
    sample_results = [{
        'target': 'scanme.nmap.org',
        'scan_type': 'service_version',
        'scan_name': 'Service Version Detection',
        'timestamp': datetime.now().isoformat(),
        'command': 'nmap -sV -v -Pn scanme.nmap.org',
        'security_context': 'Identifies specific software versions',
        'success': True,
        'host_status': 'up',
        'ports': [
            {'port': '22', 'protocol': 'tcp', 'state': 'open', 'service': 'ssh', 'version': 'OpenSSH 6.6.1'},
            {'port': '80', 'protocol': 'tcp', 'state': 'open', 'service': 'http', 'version': 'Apache 2.4.7'},
            {'port': '443', 'protocol': 'tcp', 'state': 'open', 'service': 'https', 'version': 'Apache 2.4.7'}
        ],
        'services': [],
        'warnings': []
    }]
    
    generator = PDFReportGenerator()
    output_file = "test_report.pdf"
    
    if generator.generate_report(sample_results, sample_summary, output_file):
        print(f"Test report generated: {output_file}")
