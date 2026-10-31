"""Offline protocol fixtures, NOT a transport or an authorization decision.

The wire format comes from the pinned upstream client. Handler relationships
are conditional on the separately reviewed service mapping; this model cannot
prove firmware behavior. It has no USB, network, filesystem-write or CLI path.
"""
import struct

HEADER = struct.Struct("<IHHBBBB")
COMMAND = struct.Struct("<HH")


def decode_fixture(packet):
    """Accept only the two file-read protocol messages in synthetic fixtures."""
    if len(packet) < HEADER.size + COMMAND.size:
        raise ValueError("truncated")
    size, function, sequence, version, micon, offset, response = HEADER.unpack_from(packet)
    body = packet[HEADER.size:]
    if size != len(body) or function != 0x40 or any((version, micon, offset, response)):
        raise ValueError("unsupported_header")
    category, command = COMMAND.unpack_from(body)
    if category != 0x1001 or command not in (15, 17):
        raise ValueError("outside_read_fixture_scope")
    parameters = body[COMMAND.size:]
    if command == 15:
        if len(parameters) < 3 or parameters[0] != 0 or parameters[-1] != 0:
            raise ValueError("invalid_path_record")
        path = parameters[1:-1]
        if b"\0" in path:
            raise ValueError("embedded_nul")
        return {"command": command, "path": path.decode("ascii"),
                "canonical_path_known": False}
    if len(parameters) != 3:
        raise ValueError("invalid_read_record")
    medium, selector, transfer = parameters
    return {"command": command, "medium": medium, "selector": selector,
            "transfer": transfer, "first_word": int.from_bytes(parameters[:2], "little")}


def handler_hypothesis(parameters):
    """Model observed gates IF parameters occupy internal offsets 40..42.

    A false flush gate only excludes the reviewed log-flush branch. It does not
    imply a mount-free, side-effect-free or safe camera operation.
    """
    if len(parameters) != 3:
        raise ValueError("invalid_read_record")
    return {"mode_zero_mount_path": parameters[0] == 0,
            "log_flush_gate": int.from_bytes(parameters[:2], "little") == 0x0300,
            "path_metadata_available": False}


def stat_sized_read(content, reported_size):
    """Synthetic ordinary read bounded by stat size; no read-until-EOF loop."""
    if not isinstance(reported_size, int) or not 0 <= reported_size <= 256 * 1024 * 1024:
        raise ValueError("fixture_size_bound")
    return content[:reported_size]
