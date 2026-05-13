import cbor2

from src.attestation.nsm_binding import extract_pcrs_from_attestation_document


PCR0 = bytes.fromhex("00" * 48)
PCR1 = bytes.fromhex("11" * 48)
PCR2 = bytes.fromhex("22" * 48)


def _payload():
    return {"pcrs": {0: PCR0, 1: PCR1, 2: PCR2}}


def _cose_document():
    return cbor2.dumps(cbor2.CBORTag(18, [b"protected", {}, cbor2.dumps(_payload()), b"sig"]))


def test_extract_pcrs_from_cose_attestation_document():
    pcrs = extract_pcrs_from_attestation_document(_cose_document())

    assert pcrs == {
        0: PCR0.hex(),
        1: PCR1.hex(),
        2: PCR2.hex(),
    }


def test_extract_pcrs_from_cbor_wrapped_cose_document():
    pcrs = extract_pcrs_from_attestation_document(cbor2.dumps(_cose_document()))

    assert pcrs[0] == PCR0.hex()
    assert pcrs[1] == PCR1.hex()
    assert pcrs[2] == PCR2.hex()


def test_extract_pcrs_from_payload_map():
    pcrs = extract_pcrs_from_attestation_document(cbor2.dumps(_payload()))

    assert pcrs[0] == PCR0.hex()
