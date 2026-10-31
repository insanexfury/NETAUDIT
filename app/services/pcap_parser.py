"""PyShark FileCapture parser used for genuine TShark-backed PCAP processing."""
from pathlib import Path
from threading import Event, Timer
import pyshark
from app.services.telemetry import packet_to_telemetry


class PcapParseError(Exception):
    """A safe message for corrupt captures or unavailable TShark."""


class PcapTimeoutError(PcapParseError):
    """Raised when TShark parsing exceeds the configured time limit."""


def parse_pcap(file_path: Path, timeout_seconds: int | None = None):
    """Yield extracted telemetry one packet at a time to avoid loading a whole PCAP."""
    capture = None
    timed_out = Event()
    timer = None
    try:
        capture = pyshark.FileCapture(str(file_path), keep_packets=False)
        if timeout_seconds:
            def stop_capture():
                timed_out.set()
                try:
                    capture.close()
                except (OSError, RuntimeError):
                    pass

            timer = Timer(timeout_seconds, stop_capture)
            timer.daemon = True
            timer.start()
        for packet in capture:
            if timed_out.is_set():
                raise PcapTimeoutError("PCAP analysis exceeded the configured processing time limit.")
            yield packet_to_telemetry(packet)
    except FileNotFoundError as error:
        raise PcapParseError("TShark is not installed or not available on PATH.") from error
    except PcapTimeoutError:
        raise
    except Exception as error:
        if timed_out.is_set():
            raise PcapTimeoutError("PCAP analysis exceeded the configured processing time limit.") from error
        message = str(error).lower()
        if "tshark" in message or "wireshark" in message:
            raise PcapParseError("TShark is unavailable. Install Wireshark/TShark and try again.") from error
        raise PcapParseError("Unable to parse this PCAP. It may be empty, corrupt, or unsupported.") from error
    finally:
        if timer is not None:
            timer.cancel()
        if capture is not None:
            capture.close()
