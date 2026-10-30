from reportlab.lib.colors import HexColor
from reportlab.lib.enums import TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle


OUTPUT = r"C:\MY PROJECTS\Tedis Hair Studio\output\pdf\Vincent_Pronel_Mercury_Cover_Letter.pdf"


doc = SimpleDocTemplate(
    OUTPUT,
    pagesize=LETTER,
    rightMargin=0.78 * inch,
    leftMargin=0.78 * inch,
    topMargin=0.62 * inch,
    bottomMargin=0.62 * inch,
    title="Vincent S. Pronel - Mercury Cover Letter",
    author="Vincent S. Pronel",
    subject="Application for Frontend Engineer - Design Systems",
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
    "Body", fontName="Helvetica", fontSize=9.35, leading=13.1,
    textColor=ink, alignment=TA_LEFT, spaceAfter=8.5
)
salutation_style = ParagraphStyle(
    "Salutation", parent=body_style, spaceAfter=9
)
signoff_style = ParagraphStyle(
    "Signoff", parent=body_style, spaceBefore=3, spaceAfter=0
)

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
    Paragraph("Dear Mercury Design Foundations Team,", salutation_style),
    Paragraph(
        "I am excited to apply for the Frontend Engineer, Design Systems position at Mercury. "
        "I am drawn to this role because I enjoy the point where software engineering and design meet: "
        "building interfaces that work reliably, look intentional, and feel natural to use.",
        body_style,
    ),
    Paragraph(
        "I have worked as a one-person team designing, developing, and launching websites and software "
        "from the ground up. That has meant doing much more than writing code. I have spoken with customers, "
        "turned their needs into product decisions, designed the interfaces, built the frontend, tested the "
        "experience, and carried the work through launch. I have also sold software, which taught me how "
        "strongly usability, visual quality, and trust influence whether someone sees value in a product.",
        body_style,
    ),
    Paragraph(
        "A project I am especially proud of is <link href='https://deafsharkcoffee.com' color='#0B6B57'>"
        "Deaf Shark Coffee</link>, a complete customer-facing website I designed and built for a local coffee "
        "shop. I created an experience that communicates the brand while helping customers explore the menu, "
        "learn the shop's story, find essential information, and place an order. I have also built "
        "<link href='https://adzio.io' color='#0B6B57'>Adzio</link>, "
        "<link href='https://daysicecream.com' color='#0B6B57'>Days Ice Cream</link>, and "
        "<link href='https://trainingaio.com' color='#0B6B57'>TrainingAIO</link>. Across these projects, I made "
        "the design and engineering decisions myself, creating responsive interfaces and reusable components "
        "with React, TypeScript, Next.js, HTML, CSS, and Tailwind CSS.",
        body_style,
    ),
    Paragraph(
        "Building several products independently has made me think in systems. I look for patterns that can be "
        "reused instead of solving the same interface problem repeatedly. I consider how typography, spacing, "
        "color, components, responsive behavior, and accessibility work together to create a consistent "
        "experience. It has also taught me ownership. When something is unclear or does not work, I investigate "
        "it, improve it, and follow it through.",
        body_style,
    ),
    Paragraph(
        "I regularly use AI-assisted development tools to explore solutions and move faster, but I do not treat "
        "generated code as finished work. I review it, test it in context, and refine it so that it fits the "
        "product and works as intended. Mercury's interest in design systems that support both people and AI "
        "agents is one of the most exciting parts of this opportunity for me.",
        body_style,
    ),
    Paragraph(
        "I would bring Mercury practical experience building real products, an entrepreneurial perspective from "
        "selling software, and genuine care for frontend craft. I would be excited to learn from the Design "
        "Foundations team while contributing the resourcefulness and ownership I have developed from building "
        "products independently.",
        body_style,
    ),
    Paragraph(
        "Thank you for considering my application. I would welcome the opportunity to discuss my work and how I "
        "could contribute to Mercury's design system.",
        body_style,
    ),
    Spacer(1, 4),
    Paragraph("Sincerely,<br/><br/><b>Vincent S. Pronel</b>", signoff_style),
]

doc.build(story)
print(OUTPUT)
