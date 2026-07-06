from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from aegis.database import Base


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    src_ip: Mapped[str] = mapped_column(String(45))
    dst_ip: Mapped[str] = mapped_column(String(45))
    protocol: Mapped[str] = mapped_column(String(16))
    packet_size: Mapped[int] = mapped_column(Integer, default=0)
    duration: Mapped[float] = mapped_column(Integer, default=0)
    prediction: Mapped[str] = mapped_column(String(32))
    confidence: Mapped[int] = mapped_column(Integer, default=0)
    attack_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk: Mapped[str | None] = mapped_column(String(32), nullable=True)
    action: Mapped[str | None] = mapped_column(Text, nullable=True)
    country: Mapped[str | None] = mapped_column(String(64), default="Unknown")
    isp: Mapped[str | None] = mapped_column(String(128), default="Unknown")
    is_private: Mapped[bool] = mapped_column(Boolean, default=False)
    mitre_techniques: Mapped[str | None] = mapped_column(Text, nullable=True)
    rule_hits: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="open")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)