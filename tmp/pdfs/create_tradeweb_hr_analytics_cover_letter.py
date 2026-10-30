from reportlab.lib.colors import HexColor
from reportlab.lib.enums import TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle


OUTPUT = r"C:\MY PROJECTS\Tedis Hair Studio\output\pdf\Vincent_Pronel_Tradeweb_HR_Data_Analytics_Cover_Letter.pdf"

doc = SimpleDocTemplate(
    OUTPUT,
    pagesize=LETTER,
    rightMargin=0.78 * inch,
    leftMargin=0.78 * inch,
    topMargin=0.62 * inch,
    bottomMargin=0.62 * inch,
    title="Vincent S. Pronel - Tradeweb HR Data and Analytics Cover Letter",
    author="Vincent S. Pronel",
    subject="Application for Summer 2027 Human Resources Data and Analytics Internship",
)

ink = HexColor("#152925")
muted = HexColor("#5B6865")

name_style = ParagraphStyle(
    "Name", fontName="Helvetica-Bold", fontSize=18, leading=21,
    textColor=ink, spaceAfter=2
)
date_style = ParagraphStyle(
    "Date", fontName="Helvetica", fontSize=9.2, leading=12,
    textColor=muted, alignment=TA_RIGHT
)
body_style = ParagraphStyle(
    "Body", fontName="Helvetica", fontSize=9.2, leading=12.9,
    textColor=ink, alignment=TA_LEFT, spaceAfter=8.4
)
salutation_style = ParagraphStyle("Salutation", parent=body_style, spaceAfter=9)
signoff_style = ParagraphStyle("Signoff", parent=body_style, spaceBefore=3, spaceAfter=0)

header = Table(
    [[Paragraph("Vincent S. Pronel", name_style), Paragraph("October 27, 2026", date_style)]],
    colWidths=[5.25 * inch, 1.69 * inch],
    hAlign="LEFT",
)
header.setStyle(TableStyle([
    ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ("LEFTPADDING", (0, 0), (-1, -1), 0),
    ("RIGHTPADDING", (0, 0), (-1, -1), 0),
    ("TOPPADDING", (0, 0), (-1, -1), 0),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
]))

story = [
    header,
    Spacer(1, 22),
    Paragraph("Dear Tradeweb Human Resources Team,", salutation_style),
    Paragraph(
        "I am excited to apply for the Summer 2027 Human Resources Data and Analytics Internship at Tradeweb. "
        "What interests me about this position is the opportunity to work where people, data, and technology meet. "
        "I enjoy taking information that may initially feel complicated, identifying what matters, and turning it "
        "into something people can understand and use to make a decision.",
        body_style,
    ),
    Paragraph(
        "I am a computer science student at Kean University with experience using Python, SQL, databases, and "
        "spreadsheets to organize and work with data. As a Code Samurai peer tutor, I lead two weekly technical "
        "sessions covering database systems and data structures and algorithms. That role requires me to recognize "
        "where someone is struggling, break a complex problem into understandable parts, and communicate the same "
        "idea to people with different levels of technical experience. Those are skills I would bring to reporting "
        "work and conversations with both HR and technology teams.",
        body_style,
    ),
    Paragraph(
        "My undergraduate research combines HCI, AI, and data-driven evaluation. I am studying how different "
        "GPT-based coaching configurations affect users of a debate practice application. The project has given me "
        "experience defining questions, comparing outcomes, identifying patterns, and communicating findings. It "
        "has also made me think carefully about how technology and AI can improve a process without sacrificing "
        "accuracy, context, or human judgment, which directly connects with Tradeweb's interest in improving HR "
        "reporting and operational efficiency through technology.",
        body_style,
    ),
    Paragraph(
        "Outside the classroom, I design and build software and websites for real clients. Working independently "
        "has taught me to manage projects from an unclear request through a finished product, pay attention to "
        "details, and create tools around the needs of the people using them. My earlier experience supporting "
        "technology across a school district also taught me to work professionally with user accounts, permissions, "
        "and information that had to be handled responsibly.",
        body_style,
    ),
    Paragraph(
        "I am especially interested in learning how Tradeweb uses dashboards and workforce metrics to understand "
        "talent acquisition, engagement, retention, performance, and development. I would be excited to support the "
        "collection and analysis of HR data, improve reporting workflows, and help translate trends into useful "
        "insights for workforce planning. Tradeweb's combination of hands-on projects, mentorship, and exposure to "
        "a global financial technology business makes this an opportunity where I believe I could contribute while "
        "developing into a stronger analyst.",
        body_style,
    ),
    Paragraph(
        "Thank you for considering my application. I would welcome the opportunity to discuss how my analytical "
        "foundation, communication experience, and interest in using technology to improve decisions could "
        "contribute to Tradeweb's Human Resources team.",
        body_style,
    ),
    Spacer(1, 4),
    Paragraph("Sincerely,<br/><br/><b>Vincent S. Pronel</b>", signoff_style),
]

doc.build(story)
print(OUTPUT)
