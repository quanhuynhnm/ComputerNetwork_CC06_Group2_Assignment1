"""Transport Control Block (TCB) for Raw TCP and Reliable UDP."""

from collections import OrderedDict
from dataclasses import dataclass
from enum import Enum
import threading
from typing import Dict, Optional, Tuple, Union

# Protocol constants
MAX_SEGMENT_SIZE_BYTES = 1400       # Leave room for IP/TCP headers within 1500B MTU
MAX_RECV_BUFFER_BYTES = 65535
DEFAULT_TCP_WINDOW_BYTES = 65535    # Max 16-bit TCP window size
SEQ_NUMBER_MODULO = 0xFFFFFFFF      # 32-bit sequence wrap mask

INITIAL_CWND_SEGMENTS = 2
INITIAL_RTO_SEC = 1.0
MIN_RTO_SEC = 0.2
MAX_RTO_SEC = 60.0
RTT_EWMA_ALPHA = 0.125              # SRTT smoothing factor
RTT_EWMA_BETA = 0.25                # RTTVAR smoothing factor

# (ip, port) for TCP, or (ip, port, stream_id) for multi-stream UDP
SessionKey = Union[Tuple[str, int], Tuple[str, int, int]]


class CongestionState(Enum):
    SLOW_START = "SLOW_START"
    CONGESTION_AVOIDANCE = "CONGESTION_AVOIDANCE"
    FAST_RECOVERY = "FAST_RECOVERY"


@dataclass
class UnackedSegment:
    """In-flight segment awaiting acknowledgment."""

    seq_start: int
    payload: bytes
    send_timestamp: float
    is_retransmitted: bool = False

    @property
    def length(self) -> int:
        return len(self.payload)

    @property
    def seq_end(self) -> int:
        return (self.seq_start + len(self.payload)) & SEQ_NUMBER_MODULO


class TransmissionControlBlock:
    """Transport layer state shared across Raw TCP and Reliable UDP."""

    def __init__(
        self,
        local_ip: str,
        local_port: int,
        remote_ip: str,
        remote_port: int,
        initial_send_seq: int = 0,
        initial_recv_seq: int = 0,
        stream_id: int = 0,
    ) -> None:
        self.local_ip: str = local_ip
        self.local_port: int = local_port
        self.remote_ip: str = remote_ip
        self.remote_port: int = remote_port
        self.stream_id: int = stream_id

        # Keep client_key for legacy Raw TCP logging/debugging
        self.client_key: Tuple[str, int] = (remote_ip, remote_port)
        self.session_key: SessionKey = (
            (remote_ip, remote_port) if stream_id == 0 else (remote_ip, remote_port, stream_id)
        )

        # Shared across dispatcher, app, and timer threads
        self.lock = threading.RLock()
        self.send_window_opened = threading.Condition(self.lock)
        self.recv_data_available = threading.Condition(self.lock)

        # Sequence pointers
        self.oldest_unacked_seq: int = initial_send_seq
        self.next_send_seq: int = initial_send_seq
        self.expected_remote_seq: int = initial_recv_seq

        # Reliability & RTT estimation
        self.unacked_send_buffer: "OrderedDict[int, UnackedSegment]" = OrderedDict()
        self.out_of_order_recv_buffer: Dict[int, bytes] = {}
        self.duplicate_ack_count: int = 0
        self.smoothed_rtt: Optional[float] = None
        self.rtt_variation: Optional[float] = None
        self.rto_sec: float = INITIAL_RTO_SEC

        # Flow control
        self.in_order_recv_buffer: bytearray = bytearray()
        self.peer_rwnd: int = DEFAULT_TCP_WINDOW_BYTES
        self.last_advertised_local_rwnd: int = MAX_RECV_BUFFER_BYTES
        self.last_zero_window_probe_time: float = 0.0

        # Congestion control
        self.cwnd_bytes: float = float(INITIAL_CWND_SEGMENTS * MAX_SEGMENT_SIZE_BYTES)
        self.ssthresh_bytes: int = DEFAULT_TCP_WINDOW_BYTES
        self.congestion_state: CongestionState = CongestionState.SLOW_START

    @classmethod
    def from_conn_info(cls, conn_info) -> "TransmissionControlBlock":
        """Build a TCB from a Raw TCP ConnectionInfo object."""
        return cls(
            local_ip=conn_info.server_ip,
            local_port=conn_info.server_port,
            remote_ip=conn_info.client_ip,
            remote_port=conn_info.client_port,
            initial_send_seq=conn_info.server_seq,
            initial_recv_seq=conn_info.client_seq,
            stream_id=0,
        )

    def get_local_rwnd(self) -> int:
        """Remaining free space in the local receive buffer."""
        with self.lock:
            out_of_order_bytes = sum(len(chunk) for chunk in self.out_of_order_recv_buffer.values())
            used_bytes = len(self.in_order_recv_buffer) + out_of_order_bytes
            free_bytes = MAX_RECV_BUFFER_BYTES - used_bytes
            return max(0, min(free_bytes, DEFAULT_TCP_WINDOW_BYTES))

    def get_flight_size_bytes(self) -> int:
        """Total unacknowledged bytes currently in flight."""
        with self.lock:
            return (self.next_send_seq - self.oldest_unacked_seq) & SEQ_NUMBER_MODULO

    def get_effective_window_bytes(self) -> int:
        """Effective send window capped by cwnd and peer rwnd."""
        with self.lock:
            return min(int(self.cwnd_bytes), self.peer_rwnd)

    def get_available_send_bytes(self) -> int:
        """Bytes we can transmit right now without exceeding the window."""
        with self.lock:
            effective_window = min(int(self.cwnd_bytes), self.peer_rwnd)
            in_flight = (self.next_send_seq - self.oldest_unacked_seq) & SEQ_NUMBER_MODULO
            return max(0, effective_window - in_flight)


# Global TCB registry
_tcb_registry: Dict[SessionKey, TransmissionControlBlock] = {}
_tcb_registry_lock = threading.Lock()


def create_tcb_from_conn(conn_info) -> TransmissionControlBlock:
    """Create and register a TCB after a Raw TCP handshake."""
    tcb = TransmissionControlBlock.from_conn_info(conn_info)
    with _tcb_registry_lock:
        _tcb_registry[tcb.session_key] = tcb
    return tcb


def register_tcb(tcb: TransmissionControlBlock) -> TransmissionControlBlock:
    """Register an existing TCB (e.g. for a UDP stream)."""
    with _tcb_registry_lock:
        _tcb_registry[tcb.session_key] = tcb
    return tcb


def get_tcb_by_conn(conn_info) -> Optional[TransmissionControlBlock]:
    """Look up an active Raw TCP TCB by ConnectionInfo."""
    client_key = (conn_info.client_ip, conn_info.client_port)
    with _tcb_registry_lock:
        return _tcb_registry.get(client_key)


def get_tcb_by_key(session_key: SessionKey) -> Optional[TransmissionControlBlock]:
    """Look up an active TCB by session key."""
    with _tcb_registry_lock:
        return _tcb_registry.get(session_key)


def remove_tcb_by_key(session_key: SessionKey) -> None:
    """Delete a TCB when its session closes."""
    with _tcb_registry_lock:
        _tcb_registry.pop(session_key, None)


def clear_all_tcbs() -> None:
    """Drop all active TCBs on shutdown."""
    with _tcb_registry_lock:
        _tcb_registry.clear()