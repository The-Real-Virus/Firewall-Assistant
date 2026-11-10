"""Small original line icons drawn locally; no font/icon library or remote resource."""

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPainterPath, QPen, QPixmap


def line_icon(name: str, color: str) -> QIcon:
    pixmap = QPixmap(24, 24)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setPen(
        QPen(
            QColor(color),
            1.7,
            Qt.PenStyle.SolidLine,
            Qt.PenCapStyle.RoundCap,
            Qt.PenJoinStyle.RoundJoin,
        )
    )
    if name == "Overview":
        for x, y in ((4, 4), (14, 4), (4, 14), (14, 14)):
            painter.drawRoundedRect(QRectF(x, y, 6, 6), 1, 1)
    elif name == "Diagnose":
        painter.drawEllipse(QRectF(4, 4, 12, 12))
        painter.drawLine(QPointF(14, 14), QPointF(21, 21))
        painter.drawLine(QPointF(7, 10), QPointF(13, 10))
        painter.drawLine(QPointF(10, 7), QPointF(10, 13))
    elif name == "Cases":
        path = QPainterPath(QPointF(3, 7))
        path.lineTo(9, 7)
        path.lineTo(11, 10)
        path.lineTo(21, 10)
        path.lineTo(21, 20)
        path.lineTo(3, 20)
        path.closeSubpath()
        painter.drawPath(path)
    elif name == "Compare":
        painter.drawLine(4, 8, 20, 8)
        painter.drawLine(16, 4, 20, 8)
        painter.drawLine(16, 12, 20, 8)
        painter.drawLine(4, 17, 20, 17)
        painter.drawLine(4, 17, 8, 13)
        painter.drawLine(4, 17, 8, 21)
    elif name == "AI Assistant":
        painter.drawRoundedRect(QRectF(3, 4, 18, 14), 4, 4)
        painter.drawLine(7, 18, 7, 21)
        painter.drawEllipse(QPointF(8, 11), 1, 1)
        painter.drawEllipse(QPointF(16, 11), 1, 1)
    elif name == "GitHub":
        painter.drawEllipse(QRectF(2, 2, 20, 20))
        path = QPainterPath(QPointF(8, 20))
        path.lineTo(8, 17)
        path.cubicTo(4, 17, 5, 14, 4, 14)
        path.moveTo(16, 20)
        path.lineTo(16, 17)
        path.cubicTo(21, 15, 20, 10, 18, 9)
        path.lineTo(18, 5)
        path.lineTo(14, 7)
        path.cubicTo(12, 6, 10, 7, 10, 7)
        path.lineTo(6, 5)
        path.lineTo(6, 9)
        path.cubicTo(3, 12, 5, 17, 8, 17)
        painter.drawPath(path)
    elif name == "LinkedIn":
        painter.drawRoundedRect(QRectF(3, 3, 18, 18), 2, 2)
        painter.drawEllipse(QPointF(7, 8), 0.6, 0.6)
        painter.drawLine(7, 11, 7, 17)
        painter.drawLine(11, 11, 11, 17)
        path = QPainterPath(QPointF(11, 13))
        path.cubicTo(12, 10, 17, 10, 17, 13)
        path.lineTo(17, 17)
        painter.drawPath(path)
    else:
        painter.drawEllipse(QRectF(5, 5, 14, 14))
        painter.drawEllipse(QRectF(10, 10, 4, 4))
        for x1, y1, x2, y2 in ((12, 2, 12, 5), (12, 19, 12, 22), (2, 12, 5, 12), (19, 12, 22, 12)):
            painter.drawLine(x1, y1, x2, y2)
    painter.end()
    return QIcon(pixmap)
