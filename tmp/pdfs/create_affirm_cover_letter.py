from reportlab.lib.colors import HexColor
from reportlab.lib.enums import TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle


OUTPUT = r"C:\MY PROJECTS\Tedis Hair Studio\output\pdf\Vincent_Pronel_Affirm_Cover_Letter.pdf"

doc = SimpleDocTemplate(
    OUTPUT,
    pagesize=LETTER,
    rightMargin=0.78 * inch,
    leftMargin=0.78 * inch,
    topMargin=0.62 * inch,
    bottomMargin=0.62 * inch,
    title="Vincent S. Pronel - Affirm Cover Letter",
    author="Vincent S. Pronel",
    subject="Application for Analyst, Early Career",
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
    Paragraph("Dear Affirm Risk and Analytics Team,", salutation_style),
    Paragraph(
        "I am excited to apply for the Analyst, Early Career position at Affirm. What interests me most about "
        "this role is the opportunity to use data and software to solve problems that directly affect customers "
        "and business decisions. Affirm's focus on making payments clear and predictable stands out to me because "
        "the quality of a financial product depends on people being able to understand and trust it.",
        body_style,
    ),
    Paragraph(
        "I am a computer science student at Kean University, where I have built a strong foundation in Python, "
        "SQL, databases, data structures, and algorithms. As a Code Samurai peer tutor, I lead two technical "
        "sessions each week covering database systems and data structures and algorithms. Teaching these subjects "
        "has strengthened both my technical fundamentals and my ability to break down complicated information "
        "clearly, which I know is important when turning an analysis into a useful business decision.",
        body_style,
    ),
    Paragraph(
        "My undergraduate research combines HCI, AI, and data-driven evaluation. I am studying how different "
        "GPT-based coaching configurations affect users of a debate practice application. Through this work, I "
        "have gained experience thinking through research questions, comparing system behavior, evaluating user "
        "outcomes, and communicating findings. It has also taught me to treat AI output as something that must be "
        "tested and verified rather than accepted automatically, which connects directly with Affirm's approach "
        "to using modern AI tools responsibly.",
        body_style,
    ),
    Paragraph(
        "Outside the classroom, I design and build full-stack products for real clients using React, TypeScript, "
        "Next.js, Node.js, APIs, and PostgreSQL. I built "
        "<link href='https://deafsharkcoffee.com' color='#0B6B57'>deafsharkcoffee.com</link> from the ground up "
        "and have also created <link href='https://adzio.io' color='#0B6B57'>Adzio</link>, "
        "<link href='https://daysicecream.com' color='#0B6B57'>Days Ice Cream</link>, and "
        "<link href='https://trainingaio.com' color='#0B6B57'>TrainingAIO</link>. Working independently has taught "
        "me how to take an unclear problem, identify what the user actually needs, work through the data and "
        "technical requirements, and carry a solution through deployment.",
        body_style,
    ),
    Paragraph(
        "I am especially interested in the Risk and Analytics team's responsibility for turning complex data into "
        "clear signals across fraud, customer behavior, product performance, and growth. I would be excited to "
        "strengthen my analytical skills, learn the fundamentals of consumer lending, and contribute with Python, "
        "SQL, technical curiosity, and a willingness to ask questions and improve. Affirm's early career program "
        "offers the mentorship and real ownership I am looking for as I begin my career.",
        body_style,
    ),
    Paragraph(
        "Thank you for considering my application. I would welcome the opportunity to discuss how my technical "
        "foundation, research experience, and history of independently building useful products could contribute "
        "to Affirm.",
        body_style,
    ),
    Spacer(1, 4),
    Paragraph("Sincerely,<br/><br/><b>Vincent S. Pronel</b>", signoff_style),
]

doc.build(story)
print(OUTPUT)
