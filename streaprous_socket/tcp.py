"""Transmission Control Block (TCB) management for Streaprous custom TCP layer."""

from collections import OrderedDict
from dataclasses import dataclass
from enum import Enum
import threading
from typing import Dict, Optional, Tuple

# =============================================================================
# Protocol Constants (Explicit Units)
# =============================================================================
MAX_SEGMENT_SIZE_BYTES = 1400       # MSS: 1400B + 40B IP/TCP headers < 1500B Ethernet MTU
MAX_RECV_BUFFER_BYTES = 65535       # Maximum local Server receive buffer capacity
DEFAULT_TCP_WINDOW_BYTES = 65535    # 16-bit TCP header window field max value

INITIAL_CWND_SEGMENTS = 2           # Initial congestion window in segments
INITIAL_RTO_SEC = 1.0               # Initial Retransmission Timeout (seconds)
MIN_RTO_SEC = 0.2                   # Minimum RTO lower bound
MAX_RTO_SEC = 60.0                  # Maximum RTO upper bound
RTT_EWMA_ALPHA = 0.125              # Jacobson SRTT smoothing factor
RTT_EWMA_BETA = 0.25                # Jacobson RTTVAR smoothing factor


class CongestionState(Enum):
    """Finite State Machine states for TCP Reno Congestion Control."""

    SLOW_START = "SLOW_START"
    CONGESTION_AVOIDANCE = "CONGESTION_AVOIDANCE"
    FAST_RECOVERY = "FAST_RECOVERY"


@dataclass
class UnackedSegment:
    """Represents an in-flight TCP data segment stored in the Send Buffer."""

    seq_start: int
    payload: bytes
    send_timestamp: float
    is_retransmitted: bool = False

    @property
    def length(self) -> int:
        """Return payload length in bytes."""
        return len(self.payload)

    @property
    def seq_end(self) -> int:
        """Return the sequence number immediately following this segment."""
        return self.seq_start + len(self.payload)


class TransmissionControlBlock:
    """Mutable Transport Layer state paired with an immutable ConnectionInfo.

    Indexed by client_key = (client_ip, client_port) matching the connection table.
    """

    def __init__(self, conn_info) -> None:
        """Initialize TCB state from a newly established ConnectionInfo."""
        self.client_key: Tuple[str, int] = (conn_info.client_ip, conn_info.client_port)
        self.client_ip: str = conn_info.client_ip
        self.client_port: int = conn_info.client_port
        self.server_ip: str = conn_info.server_ip
        self.server_port: int = conn_info.server_port

        # Thread synchronization across Packet Dispatcher, HttpAdapter, and Timer threads
        self.lock = threading.RLock()
        self.send_window_opened = threading.Condition(self.lock)
        self.recv_data_available = threading.Condition(self.lock)

        # Byte-stream sequence pointers (initialized after 3-way handshake)
        self.oldest_unacked_seq: int = conn_info.server_seq
        self.next_send_seq: int = conn_info.server_seq
        self.expected_client_seq: int = conn_info.client_seq

        # ---------------------------------------------------------------------
        # [Pair 1: Reliability] Buffers, Duplicate ACK tracking & RTT estimator
        # ---------------------------------------------------------------------
        self.unacked_send_buffer: "OrderedDict[int, UnackedSegment]" = OrderedDict()
        self.out_of_order_recv_buffer: Dict[int, bytes] = {}
        self.duplicate_ack_count: int = 0

        self.smoothed_rtt: Optional[float] = None
        self.rtt_variation: Optional[float] = None
        self.rto_sec: float = INITIAL_RTO_SEC

        # ---------------------------------------------------------------------
        # [Pair 2: Flow Control] Local receive buffer & Client advertised window
        # ---------------------------------------------------------------------
        self.in_order_recv_buffer: bytearray = bytearray()
        self.client_rwnd: int = DEFAULT_TCP_WINDOW_BYTES
        self.last_advertised_server_rwnd: int = MAX_RECV_BUFFER_BYTES
        self.last_zero_window_probe_time: float = 0.0

        # ---------------------------------------------------------------------
        # [Pair 3: Congestion Control] Congestion window & Reno state machine
        # ---------------------------------------------------------------------
        self.cwnd_bytes: float = float(INITIAL_CWND_SEGMENTS * MAX_SEGMENT_SIZE_BYTES)
        self.ssthresh_bytes: int = DEFAULT_TCP_WINDOW_BYTES
        self.congestion_state: CongestionState = CongestionState.SLOW_START

    # =========================================================================
    # Thread-Safe Query Helpers (Shared Interface across all 3 pairs)
    # =========================================================================
    def get_server_rwnd(self) -> int:
        """[Flow Control] Calculate remaining free bytes in Server receive buffer."""
        with self.lock:
            free_bytes = MAX_RECV_BUFFER_BYTES - len(self.in_order_recv_buffer)
            return max(0, min(free_bytes, DEFAULT_TCP_WINDOW_BYTES))

    def get_flight_size_bytes(self) -> int:
        """Return total unacknowledged bytes currently in flight."""
        with self.lock:
            return max(0, self.next_send_seq - self.oldest_unacked_seq)

    def get_effective_window_bytes(self) -> int:
        """Return the minimum of Congestion Window (cwnd) and Client RWND."""
        with self.lock:
            return min(int(self.cwnd_bytes), self.client_rwnd)

    def get_available_send_bytes(self) -> int:
        """Atomically calculate how many new bytes can be transmitted right now."""
        with self.lock:
            effective_window = min(int(self.cwnd_bytes), self.client_rwnd)
            in_flight = max(0, self.next_send_seq - self.oldest_unacked_seq)
            return max(0, effective_window - in_flight)


# =============================================================================
# Global TCB Registry (Mirrors `connections` dictionary by `client_key`)
# =============================================================================
_tcb_registry: Dict[Tuple[str, int], TransmissionControlBlock] = {}
_tcb_registry_lock = threading.Lock()


def create_tcb(conn_info) -> TransmissionControlBlock:
    """Create and register a new TCB upon 3-way handshake completion."""
    client_key = (conn_info.client_ip, conn_info.client_port)
    with _tcb_registry_lock:
        tcb = TransmissionControlBlock(conn_info)
        _tcb_registry[client_key] = tcb
        return tcb


def get_tcb_by_conn(conn_info) -> Optional[TransmissionControlBlock]:
    """Retrieve an active TCB using a ConnectionInfo instance."""
    client_key = (conn_info.client_ip, conn_info.client_port)
    with _tcb_registry_lock:
        return _tcb_registry.get(client_key)


def get_tcb_by_key(client_key: Tuple[str, int]) -> Optional[TransmissionControlBlock]:
    """Retrieve an active TCB using (client_ip, client_port)."""
    with _tcb_registry_lock:
        return _tcb_registry.get(client_key)


def remove_tcb_by_key(client_key: Tuple[str, int]) -> None:
    """Remove and clean up a TCB when its connection closes or expires."""
    with _tcb_registry_lock:
        _tcb_registry.pop(client_key, None)


def clear_all_tcbs() -> None:
    """Remove all active TCB entries during server shutdown."""
    with _tcb_registry_lock:
        _tcb_registry.clear()