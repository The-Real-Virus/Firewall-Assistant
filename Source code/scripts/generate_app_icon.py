"""Generate the original local shield/search icon; no fonts, remote assets or image libraries."""

import os
import struct
from pathlib import Path

# Build-time offscreen drawing only, never the application's private startup.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QBuffer, QIODevice, QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QGuiApplication, QImage, QPainter, QPainterPath, QPen


def png(size: int) -> bytes:
    image = QImage(size, size, QImage.Format.Format_ARGB32)
    image.fill(Qt.GlobalColor.transparent)
    painter = QPainter(image)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.scale(size / 64, size / 64)
    shield = QPainterPath(QPointF(32, 4))
    shield.lineTo(55, 13)
    shield.lineTo(53, 35)
    shield.cubicTo(51, 47, 42, 55, 32, 60)
    shield.cubicTo(22, 55, 13, 47, 11, 35)
    shield.lineTo(9, 13)
    shield.closeSubpath()
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(QColor("#1D4ED8"))
    painter.drawPath(shield)
    painter.setBrush(Qt.BrushStyle.NoBrush)
    painter.setPen(QPen(QColor("#FFFFFF"), 4, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
    painter.drawEllipse(QRectF(20, 18, 21, 21))
    painter.drawLine(QPointF(38, 36), QPointF(46, 46))
    painter.end()
    buffer = QBuffer()
    buffer.open(QIODevice.OpenModeFlag.WriteOnly)
    if not image.save(buffer, "PNG"):
        raise OSError("Local icon rendering failed")
    return bytes(buffer.data())


def main() -> None:
    app = QGuiApplication.instance() or QGuiApplication([])
    sizes = (16, 24, 32, 48, 64, 128, 256)
    images = [png(size) for size in sizes]
    offset = 6 + 16 * len(sizes)
    entries = []
    for size, data in zip(sizes, images, strict=True):
        entries.append(
            struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32, len(data), offset)
        )
        offset += len(data)
    content = struct.pack("<HHH", 0, 1, len(sizes)) + b"".join(entries) + b"".join(images)
    path = Path(__file__).resolve().parents[1] / "src/wfdiag/gui/resources/app.ico"
    path.write_bytes(content)
    print(f"Generated original icon: {len(content)} bytes, {len(sizes)} sizes")
    # Keep the application alive until all painting resources have been released.
    assert app is not None


if __name__ == "__main__":
    main()
