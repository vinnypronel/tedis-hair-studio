from reportlab.lib.colors import HexColor
from reportlab.lib.enums import TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle


OUTPUT = r"C:\MY PROJECTS\Tedis Hair Studio\output\pdf\Vincent_Pronel_Domino_Cover_Letter.pdf"

doc = SimpleDocTemplate(
    OUTPUT,
    pagesize=LETTER,
    rightMargin=0.78 * inch,
    leftMargin=0.78 * inch,
    topMargin=0.62 * inch,
    bottomMargin=0.62 * inch,
    title="Vincent S. Pronel - Domino Cover Letter",
    author="Vincent S. Pronel",
    subject="Application for Software Engineer - New Grad, 2027",
)

ink = HexColor("#152925")
green = HexColor("#0B6B57")
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
    "Body", fontName="Helvetica", fontSize=9.15, leading=12.75,
    textColor=ink, alignment=TA_LEFT, spaceAfter=8.2
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
    Paragraph("Dear Domino Engineering Team,", salutation_style),
    Paragraph(
        "I am excited to apply for the Software Engineer, New Grad 2027 position at Domino. What stands out "
        "to me about Domino is that your platform helps organizations use AI for work that genuinely matters, "
        "from developing medicine to protecting financial markets. I want to build software that does something "
        "meaningful, and the opportunity to work on the infrastructure behind mission-critical AI systems "
        "strongly interests me.",
        body_style,
    ),
    Paragraph(
        "My path into software engineering started with hardware. I spent three years working in IT, diagnosing "
        "Windows systems, repairing devices, managing network connectivity, and supporting more than 300 "
        "classroom devices across a school district. When I began studying computer science at Kean University, "
        "my first Python course shifted my interest toward software development. Since then, I have looked for "
        "every opportunity to build, research, and strengthen my technical foundation.",
        body_style,
    ),
    Paragraph(
        "Through freelance work, I have designed and developed full-stack products for real clients using React, "
        "TypeScript, Next.js, Node.js, APIs, and PostgreSQL. I built "
        "<link href='https://deafsharkcoffee.com' color='#0B6B57'>deafsharkcoffee.com</link> from the ground up "
        "and have also created <link href='https://adzio.io' color='#0B6B57'>Adzio</link>, "
        "<link href='https://daysicecream.com' color='#0B6B57'>Days Ice Cream</link>, and "
        "<link href='https://trainingaio.com' color='#0B6B57'>TrainingAIO</link>. Working independently has "
        "required me to understand user needs, make technical and design decisions, manage code through Git, "
        "integrate services, test my work, and carry products through deployment. I have also built and sold "
        "software, which taught me that reliable engineering has to solve an actual problem for the person using it.",
        body_style,
    ),
    Paragraph(
        "My current undergraduate research combines HCI and AI. I am studying how different GPT-based coaching "
        "configurations affect users of a debate practice application. This work has given me experience thinking "
        "about AI systems not only as technical tools, but as products where implementation and design decisions "
        "directly affect usefulness and trust. As a Code Samurai peer tutor, I also lead weekly sessions covering "
        "data structures, algorithms, databases, and SQL. Teaching these subjects has strengthened my fundamentals "
        "and my ability to explain technical ideas clearly.",
        body_style,
    ),
    Paragraph(
        "Domino's emphasis on giving junior engineers meaningful ownership from the beginning is especially "
        "appealing to me. I would be excited to contribute across the stack, learn unfamiliar technologies, and "
        "work alongside engineers building scalable AI infrastructure for highly regulated organizations. I would "
        "bring curiosity, resourcefulness, and the willingness to dig into difficult problems until I understand them.",
        body_style,
    ),
    Paragraph(
        "Thank you for considering my application. I would welcome the opportunity to discuss how my software "
        "development experience, AI research, and drive to keep learning could contribute to Domino.",
        body_style,
    ),
    Spacer(1, 4),
    Paragraph("Sincerely,<br/><br/><b>Vincent S. Pronel</b>", signoff_style),
]

doc.build(story)
print(OUTPUT)
