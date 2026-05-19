from sqlalchemy import Column
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import DateTime
from sqlalchemy import ForeignKey
from sqlalchemy import BigInteger
from sqlalchemy import Boolean

from sqlalchemy.orm import relationship

from datetime import datetime, UTC

from database import Base


class Device(Base):

    __tablename__ = "devices"

    id = Column(Integer, primary_key=True)

    ip = Column(String, unique=True)

    hostname = Column(String)

    mac = Column(String)

    vendor = Column(String)

    os = Column(String)

    last_seen = Column(
        DateTime,
        default=lambda: datetime.now(UTC)
    )

    services = relationship(
        "Service",
        back_populates="device",
        cascade="all, delete-orphan"
    )


class Service(Base):

    __tablename__ = "services"

    id = Column(Integer, primary_key=True)

    device_id = Column(
        Integer,
        ForeignKey("devices.id")
    )

    port = Column(Integer)

    protocol = Column(String)

    service_name = Column(String)

    product = Column(String)

    version = Column(String)

    device = relationship(
        "Device",
        back_populates="services"
    )


class Flow(Base):

    __tablename__ = "flows"

    id = Column(Integer, primary_key=True)

    src_ip = Column(String)

    dst_ip = Column(String)

    src_port = Column(Integer)

    dst_port = Column(Integer)

    protocol = Column(String)

    packet_count = Column(
        Integer,
        default=0
    )

    byte_count = Column(
        BigInteger,
        default=0
    )

    first_seen = Column(DateTime)

    last_seen = Column(DateTime)

    src_is_internal = Column(
        Boolean,
        default=False
    )

    dst_is_internal = Column(
        Boolean,
        default=False
    )

    src_asn = Column(String)

    src_org = Column(String)

    src_country = Column(String)

    src_rdns = Column(String)

    dst_asn = Column(String)

    dst_org = Column(String)

    dst_country = Column(String)

    dst_rdns = Column(String)
