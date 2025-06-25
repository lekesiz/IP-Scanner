import os
import json
from datetime import datetime
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')  # GUI olmadan çalışması için

class ReportGenerator:
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.setup_custom_styles()
    
    def setup_custom_styles(self):
        """Özel stil tanımlamaları"""
        self.title_style = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.darkblue
        )
        
        self.heading_style = ParagraphStyle(
            'CustomHeading',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            textColor=colors.darkblue
        )
        
        self.normal_style = ParagraphStyle(
            'CustomNormal',
            parent=self.styles['Normal'],
            fontSize=10,
            spaceAfter=6
        )
    
    def generate_pdf_report(self, devices, stats, output_path="scan_report.pdf"):
        """PDF raporu oluşturur"""
        doc = SimpleDocTemplate(output_path, pagesize=A4)
        story = []
        
        # Başlık
        title = Paragraph("IP Scanner V3.2 - Ağ Tarama Raporu", self.title_style)
        story.append(title)
        story.append(Spacer(1, 20))
        
        # Rapor bilgileri
        report_info = [
            ["Rapor Tarihi:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
            ["Toplam Cihaz:", str(stats.get('total_devices', 0))],
            ["Tarama Aralığı:", "192.168.1.0/24"],
            ["Rapor Türü:", "Detaylı Ağ Analizi"]
        ]
        
        info_table = Table(report_info, colWidths=[2*inch, 4*inch])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightblue),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('BACKGROUND', (0, 0), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(info_table)
        story.append(Spacer(1, 20))
        
        # İstatistikler
        stats_heading = Paragraph("Ağ İstatistikleri", self.heading_style)
        story.append(stats_heading)
        
        # Cihaz türü dağılımı
        if stats.get('device_types'):
            device_types_data = [["Cihaz Türü", "Sayı"]]
            for device_type, count in stats['device_types'].items():
                device_types_data.append([device_type, str(count)])
            
            device_table = Table(device_types_data, colWidths=[3*inch, 1*inch])
            device_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(device_table)
            story.append(Spacer(1, 15))
        
        # Cihaz listesi
        devices_heading = Paragraph("Tespit Edilen Cihazlar", self.heading_style)
        story.append(devices_heading)
        
        if devices:
            # Tablo başlıkları
            device_data = [["IP Adresi", "MAC Adresi", "Üretici", "Cihaz Türü", "Açık Portlar"]]
            
            for device in devices:
                open_ports = ", ".join(map(str, device.get('open_ports', []))) if device.get('open_ports') else "Yok"
                device_data.append([
                    device['ip'],
                    device['mac'],
                    device['vendor'],
                    device['device_type'],
                    open_ports
                ])
            
            # Cihaz tablosu
            device_table = Table(device_data, colWidths=[1.2*inch, 1.5*inch, 1.5*inch, 1.2*inch, 1.2*inch])
            device_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
            ]))
            story.append(device_table)
        
        # PDF oluştur
        doc.build(story)
        return output_path
    
    def generate_html_report(self, devices, stats, output_path="scan_report.html"):
        """HTML raporu oluşturur"""
        html_content = f"""
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>IP Scanner V3.2 - Ağ Tarama Raporu</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 20px; margin-bottom: 30px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
        .stat-card {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; text-align: center; }}
        .stat-card h3 {{ margin: 0; font-size: 2em; }}
        .stat-card p {{ margin: 5px 0 0 0; opacity: 0.9; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #3498db; color: white; }}
        tr:nth-child(even) {{ background-color: #f2f2f2; }}
        tr:hover {{ background-color: #e8f4fd; }}
        .section {{ margin: 30px 0; }}
        .section h2 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
        .timestamp {{ color: #7f8c8d; font-style: italic; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>IP Scanner V3.2 - Ağ Tarama Raporu</h1>
            <p class="timestamp">Oluşturulma Tarihi: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
        
        <div class="section">
            <h2>Ağ İstatistikleri</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <h3>{stats.get('total_devices', 0)}</h3>
                    <p>Toplam Cihaz</p>
                </div>
                <div class="stat-card">
                    <h3>{len(stats.get('device_types', {}))}</h3>
                    <p>Cihaz Türü</p>
                </div>
                <div class="stat-card">
                    <h3>{len(stats.get('vendors', {}))}</h3>
                    <p>Farklı Üretici</p>
                </div>
                <div class="stat-card">
                    <h3>{len(stats.get('open_ports', {}))}</h3>
                    <p>Açık Port</p>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>Cihaz Türü Dağılımı</h2>
            <table>
                <tr><th>Cihaz Türü</th><th>Sayı</th></tr>
        """
        
        for device_type, count in stats.get('device_types', {}).items():
            html_content += f"<tr><td>{device_type}</td><td>{count}</td></tr>"
        
        html_content += """
            </table>
        </div>
        
        <div class="section">
            <h2>Tespit Edilen Cihazlar</h2>
            <table>
                <tr>
                    <th>IP Adresi</th>
                    <th>MAC Adresi</th>
                    <th>Üretici</th>
                    <th>Cihaz Türü</th>
                    <th>Açık Portlar</th>
                </tr>
        """
        
        for device in devices:
            open_ports = ", ".join(map(str, device.get('open_ports', []))) if device.get('open_ports') else "Yok"
            html_content += f"""
                <tr>
                    <td>{device['ip']}</td>
                    <td>{device['mac']}</td>
                    <td>{device['vendor']}</td>
                    <td>{device['device_type']}</td>
                    <td>{open_ports}</td>
                </tr>
            """
        
        html_content += """
            </table>
        </div>
    </div>
</body>
</html>
        """
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_path
    
    def create_charts(self, stats, output_dir="webapp/static"):
        """İstatistik grafikleri oluşturur"""
        os.makedirs(output_dir, exist_ok=True)
        
        # Cihaz türü dağılımı grafiği
        if stats.get('device_types'):
            plt.figure(figsize=(10, 6))
            device_types = list(stats['device_types'].keys())
            counts = list(stats['device_types'].values())
            
            plt.pie(counts, labels=device_types, autopct='%1.1f%%', startangle=90)
            plt.title('Cihaz Türü Dağılımı')
            plt.axis('equal')
            
            chart_path = os.path.join(output_dir, 'device_types_chart.png')
            plt.savefig(chart_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            return chart_path
        
        return None
    
    def send_email_report(self, to_email, subject, body, attachment_path=None, smtp_config=None):
        """E-posta ile rapor gönderir"""
        if not smtp_config:
            return False
        
        try:
            msg = MIMEMultipart()
            msg['From'] = smtp_config['email']
            msg['To'] = to_email
            msg['Subject'] = subject
            
            msg.attach(MIMEText(body, 'html'))
            
            if attachment_path and os.path.exists(attachment_path):
                with open(attachment_path, "rb") as attachment:
                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(attachment.read())
                
                encoders.encode_base64(part)
                part.add_header(
                    'Content-Disposition',
                    f'attachment; filename= {os.path.basename(attachment_path)}'
                )
                msg.attach(part)
            
            server = smtplib.SMTP(smtp_config['smtp_server'], smtp_config['smtp_port'])
            server.starttls()
            server.login(smtp_config['email'], smtp_config['password'])
            text = msg.as_string()
            server.sendmail(smtp_config['email'], to_email, text)
            server.quit()
            
            return True
            
        except Exception as e:
            print(f"E-posta gönderme hatası: {str(e)}")
            return False

def generate_reports(devices, stats, output_dir="reports"):
    """Ana fonksiyon: Tüm raporları oluşturur"""
    os.makedirs(output_dir, exist_ok=True)
    
    generator = ReportGenerator()
    
    # PDF raporu
    pdf_path = os.path.join(output_dir, f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
    pdf_file = generator.generate_pdf_report(devices, stats, pdf_path)
    
    # HTML raporu
    html_path = os.path.join(output_dir, f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
    html_file = generator.generate_html_report(devices, stats, html_path)
    
    # Grafik
    chart_path = generator.create_charts(stats)
    
    return {
        'pdf': pdf_file,
        'html': html_file,
        'chart': chart_path
    } 