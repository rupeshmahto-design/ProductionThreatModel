"""
PDF Generation for Threat Assessment Reports
Uses ReportLab for pure Python PDF generation
"""

import io
import re
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY


def create_reportlab_table(table_data):
    """Create a ReportLab Table object from table data"""
    if not table_data or len(table_data) < 1:
        return None
    
    # Clean cells and wrap in Paragraphs for better text wrapping
    from reportlab.lib.styles import getSampleStyleSheet
    styles = getSampleStyleSheet()
    cell_style = ParagraphStyle(
        'CellStyle',
        parent=styles['Normal'],
        fontSize=7,
        leading=9,
        alignment=TA_LEFT
    )
    
    cleaned_data = []
    for row_idx, row in enumerate(table_data):
        cleaned_row = []
        for cell in row:
            # Remove markdown formatting
            cell_text = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', str(cell))
            cell_text = re.sub(r'\*(.*?)\*', r'<i>\1</i>', cell_text)
            cell_text = cell_text.replace('`', '')
            
            # Apply color to risk levels
            cell_text = re.sub(r'\b(CRITICAL)\b', r'<font color="#dc2626"><b>\1</b></font>', cell_text)
            cell_text = re.sub(r'\b(HIGH)\b', r'<font color="#ea580c"><b>\1</b></font>', cell_text)
            cell_text = re.sub(r'\b(MEDIUM)\b', r'<font color="#ca8a04"><b>\1</b></font>', cell_text)
            cell_text = re.sub(r'\b(LOW)\b', r'<font color="#16a34a"><b>\1</b></font>', cell_text)
            
            # Wrap in Paragraph for better text handling
            if row_idx == 0:
                # Header row - bold and centered
                header_style = ParagraphStyle('HeaderStyle', parent=cell_style, fontSize=7, fontName='Helvetica-Bold', alignment=TA_CENTER)
                cleaned_row.append(Paragraph(cell_text, header_style))
            else:
                cleaned_row.append(Paragraph(cell_text, cell_style))
        cleaned_data.append(cleaned_row)
    
    # Determine column count and set dynamic widths
    num_cols = len(cleaned_data[0]) if cleaned_data else 0
    if num_cols == 0:
        return None
    
    # Set column widths based on number of columns
    page_width = 7.0 * inch  # letter size minus margins
    if num_cols <= 3:
        col_widths = [page_width / num_cols] * num_cols
    elif num_cols <= 5:
        # More columns - make first column slightly wider
        col_widths = [1.2*inch] + [(page_width - 1.2*inch) / (num_cols - 1)] * (num_cols - 1)
    else:
        # Many columns - equal width
        col_widths = [page_width / num_cols] * num_cols
    
    # Create table with column widths
    table = Table(cleaned_data, colWidths=col_widths, repeatRows=1)
    
    # Style table
    style = TableStyle([
        # Header row
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 9),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('TOPPADDING', (0, 0), (-1, 0), 8),
        
        # Data rows
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
        ('ALIGN', (0, 1), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 8),
        ('TOPPADDING', (0, 1), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 5),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        
        # Grid
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        
        # Alternating row colors
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
    ])
    
    table.setStyle(style)
    return table


def generate_pdf(report_content: str, project_name: str, framework: str = "MITRE ATT&CK") -> bytes:
    """Generate a professional PDF from markdown threat assessment report"""
    
    # Create PDF buffer
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, 
        pagesize=letter, 
        topMargin=0.75*inch, 
        bottomMargin=0.75*inch,
        leftMargin=0.75*inch, 
        rightMargin=0.75*inch
    )
    
    # Styles
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=20,
        textColor=colors.HexColor('#1a202c'),
        spaceAfter=14,
        spaceBefore=8,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    )
    
    subtitle_style = ParagraphStyle(
        'CustomSubtitle',
        parent=styles['Normal'],
        fontSize=12,
        textColor=colors.HexColor('#4a5568'),
        spaceAfter=20,
        alignment=TA_CENTER,
        fontName='Helvetica'
    )
    
    heading1_style = ParagraphStyle(
        'CustomHeading1',
        parent=styles['Heading1'],
        fontSize=15,
        textColor=colors.HexColor('#1e40af'),
        spaceBefore=16,
        spaceAfter=8,
        fontName='Helvetica-Bold'
    )
    
    heading2_style = ParagraphStyle(
        'CustomHeading2',
        parent=styles['Heading2'],
        fontSize=12,
        textColor=colors.HexColor('#2563eb'),
        spaceBefore=12,
        spaceAfter=6,
        fontName='Helvetica-Bold'
    )
    
    heading3_style = ParagraphStyle(
        'CustomHeading3',
        parent=styles['Heading3'],
        fontSize=10,
        textColor=colors.HexColor('#3b82f6'),
        spaceBefore=8,
        spaceAfter=4,
        fontName='Helvetica-Bold'
    )
    
    body_style = ParagraphStyle(
        'CustomBody',
        parent=styles['BodyText'],
        fontSize=9,
        leading=12,
        alignment=TA_LEFT,
        spaceAfter=6,
        fontName='Helvetica'
    )
    
    # Build content
    story = []
    
    # Title page
    story.append(Spacer(1, 0.5*inch))
    story.append(Paragraph("🛡️ THREAT ASSESSMENT REPORT", title_style))
    story.append(Spacer(1, 0.15*inch))
    story.append(Paragraph(f"<b>Project:</b> {project_name}", subtitle_style))
    story.append(Paragraph(f"<b>Framework:</b> {framework}", subtitle_style))
    story.append(Paragraph(f"<b>Generated:</b> {datetime.now().strftime('%B %d, %Y at %I:%M %p')}", subtitle_style))
    story.append(Spacer(1, 0.3*inch))
    story.append(Paragraph("<i>This report contains a comprehensive threat analysis based on industry-standard security frameworks and AI-powered assessment.</i>", body_style))
    story.append(Spacer(1, 0.5*inch))
    
    # Parse markdown content
    lines = report_content.split('\n')
    current_table = []
    in_table = False
    
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        
        # Skip table separator lines (---|---|---)
        if re.match(r'^[\|\s\-:]+$', line) and '|' in line:
            i += 1
            continue
        
        # Empty lines
        if not line:
            if not in_table:
                story.append(Spacer(1, 0.1*inch))
            i += 1
            continue
        
        # Headers
        if line.startswith('# ') and not line.startswith('## '):
            if current_table:
                table_element = create_reportlab_table(current_table)
                if table_element:
                    story.append(table_element)
                    story.append(Spacer(1, 0.15*inch))
                current_table = []
                in_table = False
            content = line[2:].replace('🛡️', '').replace('🔍', '').replace('📊', '').strip()
            story.append(Spacer(1, 0.2*inch))
            story.append(Paragraph(content, heading1_style))
            
        elif line.startswith('## ') and not line.startswith('### '):
            if current_table:
                table_element = create_reportlab_table(current_table)
                if table_element:
                    story.append(table_element)
                    story.append(Spacer(1, 0.12*inch))
                current_table = []
                in_table = False
            content = line[3:].replace('🎯', '').replace('⚠️', '').replace('✅', '').strip()
            story.append(Paragraph(content, heading2_style))
            
        elif line.startswith('### '):
            if current_table:
                table_element = create_reportlab_table(current_table)
                if table_element:
                    story.append(table_element)
                    story.append(Spacer(1, 0.1*inch))
                current_table = []
                in_table = False
            content = line[4:].replace('🔴', '').replace('🟠', '').replace('🟡', '').strip()
            story.append(Paragraph(content, heading3_style))
        
        # Table rows
        elif '|' in line and line.count('|') >= 2:
            in_table = True
            cells = [cell.strip() for cell in line.split('|') if cell.strip()]
            if cells:
                current_table.append(cells)
                # Add page break hint for very long tables (>15 rows)
                if len(current_table) > 15 and len(current_table) % 15 == 0:
                    table_element = create_reportlab_table(current_table)
                    if table_element:
                        story.append(table_element)
                        story.append(PageBreak())
                    current_table = [current_table[0]]  # Keep header for next page
        
        # Regular text
        else:
            if in_table and current_table:
                table_element = create_reportlab_table(current_table)
                if table_element:
                    story.append(table_element)
                    story.append(Spacer(1, 0.12*inch))
                current_table = []
                in_table = False
            
            # Format inline markdown
            line = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', line)
            line = re.sub(r'\*(.+?)\*', r'<i>\1</i>', line)
            line = re.sub(r'`(.+?)`', r'<font face="Courier" size="8">\1</font>', line)
            
            # Remove emojis
            line = re.sub(r'[🔴🟠🟡🟢🔵⚪🎯⚠️✅❌📊🔍🛡️📝🔐💡]', '', line)
            
            # Apply color formatting for risk levels
            line = re.sub(r'\b(CRITICAL)\b', r'<font color="#dc2626"><b>\1</b></font>', line)
            line = re.sub(r'\b(HIGH)\b', r'<font color="#ea580c"><b>\1</b></font>', line)
            line = re.sub(r'\b(MEDIUM)\b', r'<font color="#ca8a04"><b>\1</b></font>', line)
            line = re.sub(r'\b(LOW)\b', r'<font color="#16a34a"><b>\1</b></font>', line)
            line = re.sub(r'\b(P0)\b', r'<font color="#dc2626"><b>\1</b></font>', line)
            line = re.sub(r'\b(P1)\b', r'<font color="#ea580c"><b>\1</b></font>', line)
            line = re.sub(r'\b(P2)\b', r'<font color="#ca8a04"><b>\1</b></font>', line)
            
            if line:
                story.append(Paragraph(line, body_style))
        
        i += 1
    
    # Add any remaining table
    if current_table:
        table_element = create_reportlab_table(current_table)
        if table_element:
            story.append(table_element)
    
    # Build PDF
    doc.build(story)
    
    # Get PDF bytes
    pdf_bytes = buffer.getvalue()
    buffer.close()
    
    return pdf_bytes
