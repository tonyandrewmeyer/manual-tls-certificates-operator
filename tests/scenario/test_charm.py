# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

import base64
import json

import ops
import pytest
import scenario

from charm import ManualTLSCertificatesCharm


def _decode_from_base64(bytes_content: bytes) -> str:
    return bytes_content.decode("utf-8")


def _encode_in_base64(string_content: str) -> bytes:
    """Decodes given string to Base64.

    Args:
        string_content (str): String content

    Returns:
        bytes: bytes
    """
    return base64.b64encode(string_content.encode("utf-8"))


def get_certificate_from_file(filename: str) -> str:
    with open(filename, "r") as file:
        certificate = file.read()
    return certificate


"""
    self.harness = testing.Harness(ManualTLSCertificatesCharm)
    self.addCleanup(self.harness.cleanup)
    self.harness.set_leader(True)
    self.harness.begin()

    csr = get_certificate_from_file(filename="tests/csr.pem")
    csr_bytes = _encode_in_base64(csr)
    certificate = get_certificate_from_file(filename="tests/certificate.pem")
    certificate_bytes = _encode_in_base64(certificate)
    ca_certificate = get_certificate_from_file(filename="tests/ca_certificate.pem")
    ca_certificate_bytes = _encode_in_base64(ca_certificate)
    ca_chain = get_certificate_from_file(filename="tests/ca_chain.pem")
    ca_chain_bytes = _encode_in_base64(ca_chain)

    self.decoded_csr = _decode_from_base64(csr_bytes)
    self.decoded_certificate = _decode_from_base64(certificate_bytes)
    self.decoded_ca_certificate = _decode_from_base64(ca_certificate_bytes)
    self.decoded_ca_chain = _decode_from_base64(ca_chain_bytes)
"""


def test_given_outstanding_requests_when_certificate_creation_request_then_status_is_active():
    ctx = scenario.Context(ManualTLSCertificatesCharm)
    relation = scenario.Relation(
        # SCENARIO-NOTE: this is in the Harness test, but it seems like it could
        # be left out if the ID was automatic.
        relation_id=1234,
        # SCENARIO-NOTE: 'endpoint' is an unfamiliar name to me in this context.
        endpoint="certificates",
        remote_app_name="application",
        remote_units_data={
            0: {
                "certificate_signing_requests": json.dumps(
                    [{"certificate_signing_request": "some csr"}]
                )
            }
        },
    )
    state = scenario.State(relations=[relation], leader=True)
    out = ctx.run(relation.changed_event(), state=state)
    # It seems like this ought to be WaitingStatus?
    assert out.unit_status == ops.ActiveStatus(
        "1 outstanding requests, use juju actions to provide certificates"
    )


# SCENARIO-NOTE: I don't think this really happens. The active status is set in
# three situations: at the completion of an action successfully setting the
# certificate, after relation-departed completes (which is clearly not what this
# test is intending) and on relation-changed if there is a successful request.
# I think this is not really an issue with Scenario and more that it's testing
# the wrong thing - it should either test that a certificate is successfully
# added if there's data in the relation (there's a success test below, but it's
# for the action), or test that the status is correct when there is no relation
# ("charm is deployed" hints at an install event, which is active with a
# message of "Ready to provide certificates.") or the relation data is empty
# (when the status is unknown).
@pytest.mark.skip("Unsuitable for Scenario")
def test_given_no_units_with_no_certs_when_charm_is_deployed_then_status_is_active_and_no_outstanding_requests():  # noqa: E501
    ctx = scenario.Context(ManualTLSCertificatesCharm)
    state = scenario.State(leader=True)
    out = ctx.run(scenario.Event("install"), state=state)
    assert out.unit_status == ops.ActiveStatus("No outstanding requests.")


def test_given_no_requirer_application_when_get_outstanding_certificate_requests_action_then_event_fails():  # noqa: E501
    # SCENARIO-NOTE: do the docs mention anywhere what happens if you don't provide meta?
    ctx = scenario.Context(ManualTLSCertificatesCharm)
    out = ctx.run_action("get-outstanding-certificate-requests", scenario.State())
    assert not out.success
    assert out.failure == "No certificates relation has been created yet."


@pytest.mark.skip("Unsuitable for Scenario")
def test_given_non_json_serializable_data_when_get_outstanding_certificate_requests_action_then_event_fails():  # noqa: E501
    ctx = scenario.Context(ManualTLSCertificatesCharm)
    # SCENARIO-NOTE: there's no way to simulate what this test needs (without
    # doing a patch as the Harness test does, which doesn't seem to align with
    # the Scenario intent). The `get_outstanding_certificate_requests()` method
    # will always return a list of dicts with string keys and values that are
    # either str or int, or have been JSON-loaded from relation data, so must
    # in turn be able to be serialised to JSON. Should this be a Harness test?
    # What's the motivation for having the action handler explicitly handle
    # these cases - maybe there once was a way to make this happen?
    # It is possible to get the "Failed to parse outstanding requests" error
    # with other relation data (e.g. "certificates_signing_requests" being a
    # plain string), but that's not testing the JSON case.
    relation = scenario.Relation(
        # SCENARIO-NOTE: 'endpoint' is an unfamiliar name to me in this context.
        endpoint="certificates",
        remote_app_name="requirer",
    )
    state = scenario.State(relations=[relation])
    out = ctx.run_action("get-outstanding-certificate-requests", state)
    assert not out.success
    assert out.failure == "Failed to parse outstanding requests"


def test_given_requirer_application_when_get_outstanding_certificate_requests_action_then_csrs_information_is_returned():  # noqa: E501
    example_unit_csrs = [
        {
            "relation_id": 1234,
            # SCENARIO-NOTE: in the Harness test, this is 'unit/0', but I don't
            # think you can actually name units with Juju?
            "unit_name": "application/0",
            "application_name": "application",
            "unit_csrs": [{"certificate_signing_request": "some csr"}],
        }
    ]
    ctx = scenario.Context(ManualTLSCertificatesCharm)
    # SCENARIO-NOTE: converting this test was a little tricky, because the
    # Harness test doesn't set up the relation data, it mocks the return value
    # for a method that processes the relation data. Harness and Scenario can
    # equally do this by setting up the relation data, but it seems like the
    # mocking approach doesn't suit Scenario - is that an issue?
    relation = scenario.Relation(
        # SCENARIO-NOTE: this is in the Harness test, but it seems like it could
        # be left out if the ID was automatic.
        relation_id=1234,
        # SCENARIO-NOTE: 'endpoint' is an unfamiliar name to me in this context.
        endpoint="certificates",
        remote_app_name="application",
        remote_units_data={
            0: {
                "certificate_signing_requests": json.dumps(
                    [{"certificate_signing_request": "some csr"}]
                )
            }
        },
    )
    state = scenario.State(relations=[relation])
    out = ctx.run_action("get-outstanding-certificate-requests", state)
    assert out.success
    assert json.loads(out.results["result"]) == example_unit_csrs


def test_given_requirer_and_no_outstanding_certs_when_get_outstanding_certificate_requests_action_then_empty_list_is_returned():  # noqa: E501
    ctx = scenario.Context(ManualTLSCertificatesCharm)
    relation = scenario.Relation(
        # SCENARIO-NOTE: 'endpoint' is an unfamiliar name to me in this context.
        endpoint="certificates",
        remote_app_name="requirer",
        remote_units_data={0: {"certificate_signing_requests": json.dumps([])}},
    )
    state = scenario.State(relations=[relation])
    out = ctx.run_action("get-outstanding-certificate-requests", state)
    assert out.success
    assert json.loads(out.results["result"]) == []


def test_given_relation_id_not_exist_when_get_outstanding_certificate_requests_action_then_action_returns_empty_list():  # noqa: E501
    ctx = scenario.Context(ManualTLSCertificatesCharm)
    relation = scenario.Relation(
        # SCENARIO-NOTE: 'endpoint' is an unfamiliar name to me in this context.
        endpoint="certificates",
        remote_app_name="requirer",
    )
    state = scenario.State(relations=[relation])
    action = scenario.Action("get-outstanding-certificate-requests", params={"relation-id": 1235})
    out = ctx.run_action(action, state)
    assert out.success
    assert json.loads(out.results["result"]) == []


@pytest.fixture()
def certificates():
    csr = get_certificate_from_file(filename="tests/csr.pem")
    csr_bytes = _encode_in_base64(csr)
    certificate = get_certificate_from_file(filename="tests/certificate.pem")
    certificate_bytes = _encode_in_base64(certificate)
    ca_certificate = get_certificate_from_file(filename="tests/ca_certificate.pem")
    ca_certificate_bytes = _encode_in_base64(ca_certificate)
    ca_chain = get_certificate_from_file(filename="tests/ca_chain.pem")
    ca_chain_bytes = _encode_in_base64(ca_chain)

    decoded_csr = _decode_from_base64(csr_bytes)
    decoded_certificate = _decode_from_base64(certificate_bytes)
    decoded_ca_certificate = _decode_from_base64(ca_certificate_bytes)
    decoded_ca_chain = _decode_from_base64(ca_chain_bytes)

    return {
        "decoded_csr": decoded_csr,
        "decoded_certificate": decoded_certificate,
        "decoded_ca_certificate": decoded_ca_certificate,
        "decoded_ca_chain": decoded_ca_chain,
        "csr": csr,
        "certificate": certificate,
        "ca_certificate": ca_certificate,
        "ca_chain": ca_chain,
    }


def test_given_relation_not_created_when_provide_certificate_action_then_event_fails(certificates):
    decoded_csr = certificates["decoded_csr"]
    decoded_certificate = certificates["decoded_certificate"]
    decoded_ca_certificate = certificates["decoded_ca_certificate"]
    decoded_ca_chain = certificates["decoded_ca_chain"]

    ctx = scenario.Context(ManualTLSCertificatesCharm)
    action = scenario.Action(
        "provide-certificate",
        params={
            "certificate-signing-request": decoded_csr,
            "certificate": decoded_certificate,
            "ca-certificate": decoded_ca_certificate,
            "ca-chain": decoded_ca_chain,
            "relation-id": 1234,
        },
    )
    out = ctx.run_action(action, scenario.State())
    assert not out.success
    assert out.failure == "No certificates relation has been created yet."


def test_given_certificate_not_encoded_correctly_when_provide_certificate_action_then_action_fails():  # noqa: E501
    ctx = scenario.Context(ManualTLSCertificatesCharm)
    relation = scenario.Relation(
        # SCENARIO-NOTE: 'endpoint' is an unfamiliar name to me in this context.
        endpoint="certificates",
        remote_app_name="requirer",
    )
    state = scenario.State(relations=[relation])
    action = scenario.Action(
        "provide-certificate",
        params={
            "certificate-signing-request": "wrong encoding",
            "certificate": "wrong encoding",
            "ca-certificate": "wrong encoding",
            "ca-chain": "wrong encoding",
            "relation-id": 1234,
        },
    )
    out = ctx.run_action(action, state=state)
    assert not out.success
    assert out.failure == "Action input is not valid."


def test_given_csr_does_not_exist_in_requirer_when_provide_certificate_action_then_event_fails(
    certificates,
):
    decoded_csr = certificates["decoded_csr"]
    decoded_certificate = certificates["decoded_certificate"]
    decoded_ca_certificate = certificates["decoded_ca_certificate"]
    decoded_ca_chain = certificates["decoded_ca_chain"]

    ctx = scenario.Context(ManualTLSCertificatesCharm)
    relation = scenario.Relation(
        # SCENARIO-NOTE: 'endpoint' is an unfamiliar name to me in this context.
        endpoint="certificates",
        remote_app_name="requirer",
        remote_units_data={0: {"certificate_signing_requests": json.dumps([])}},
    )
    state = scenario.State(relations=[relation])
    action = scenario.Action(
        "provide-certificate",
        params={
            "certificate-signing-request": decoded_csr,
            "certificate": decoded_certificate,
            "ca-certificate": decoded_ca_certificate,
            "ca-chain": decoded_ca_chain,
            # SCENARIO-NOTE: it seems like this would be more natural as `relation.id`?
            "relation-id": relation.relation_id,
        },
    )
    out = ctx.run_action(action, state=state)
    assert not out.success
    assert out.failure == "Certificate signing request was not found in requirer data."


def test_given_not_matching_csr_and_certificate_when_provide_certificate_action_then_event_fails(
    certificates,
):  # noqa: E501
    decoded_csr = certificates["decoded_csr"]
    decoded_ca_certificate = certificates["decoded_ca_certificate"]
    decoded_ca_chain = certificates["decoded_ca_chain"]
    csr_from_file = get_certificate_from_file(filename="tests/csr.pem")

    ctx = scenario.Context(ManualTLSCertificatesCharm)
    relation = scenario.Relation(
        # SCENARIO-NOTE: 'endpoint' is an unfamiliar name to me in this context.
        endpoint="certificates",
        remote_app_name="requirer",
        remote_units_data={
            0: {
                "certificate_signing_requests": json.dumps(
                    [{"certificate_signing_request": csr_from_file}]
                )
            }
        },
    )
    state = scenario.State(relations=[relation])
    action = scenario.Action(
        "provide-certificate",
        params={
            "certificate-signing-request": decoded_csr,
            "certificate": decoded_ca_certificate,
            "ca-certificate": decoded_ca_certificate,
            "ca-chain": decoded_ca_chain,
            # SCENARIO-NOTE: it seems like this would be more natural as `relation.id`?
            "relation-id": relation.relation_id,
        },
    )
    out = ctx.run_action(action, state=state)
    assert not out.success
    assert out.failure == "Certificate and CSR do not match."


def test_given_invalid_ca_chain_when_provide_certificate_action_then_event_fails(certificates):
    decoded_csr = certificates["decoded_csr"]
    decoded_certificate = certificates["decoded_certificate"]
    decoded_ca_certificate = certificates["decoded_ca_certificate"]
    decoded_ca_chain = certificates["decoded_ca_chain"]
    # Make the chain bad.
    decoded_ca_chain = f".{decoded_ca_chain[1:]}"
    csr_from_file = get_certificate_from_file(filename="tests/csr.pem")

    ctx = scenario.Context(ManualTLSCertificatesCharm)
    relation = scenario.Relation(
        # SCENARIO-NOTE: 'endpoint' is an unfamiliar name to me in this context.
        endpoint="certificates",
        remote_app_name="requirer",
        remote_units_data={
            0: {
                "certificate_signing_requests": json.dumps(
                    [{"certificate_signing_request": csr_from_file}]
                )
            }
        },
    )
    state = scenario.State(relations=[relation])
    action = scenario.Action(
        "provide-certificate",
        params={
            "certificate-signing-request": decoded_csr,
            "certificate": decoded_certificate,
            "ca-certificate": decoded_ca_certificate,
            "ca-chain": decoded_ca_chain,
            # SCENARIO-NOTE: it seems like this would be more natural as `relation.id`?
            "relation-id": relation.relation_id,
        },
    )
    out = ctx.run_action(action, state=state)
    assert not out.success
    assert out.failure == "Action input is not valid."


def test_given_valid_input_when_provide_certificate_action_then_certificate_is_provided(
    certificates,
):
    decoded_csr = certificates["decoded_csr"]
    decoded_certificate = certificates["decoded_certificate"]
    decoded_ca_certificate = certificates["decoded_ca_certificate"]
    decoded_ca_chain = certificates["decoded_ca_chain"]
    csr_from_file = get_certificate_from_file(filename="tests/csr.pem")
    ctx = scenario.Context(ManualTLSCertificatesCharm)
    relation = scenario.Relation(
        # SCENARIO-NOTE: 'endpoint' is an unfamiliar name to me in this context.
        endpoint="certificates",
        remote_app_name="requirer",
        remote_units_data={
            0: {
                "certificate_signing_requests": json.dumps(
                    [{"certificate_signing_request": csr_from_file}]
                )
            }
        },
    )
    state = scenario.State(relations=[relation], leader=True)
    action = scenario.Action(
        "provide-certificate",
        params={
            "certificate-signing-request": decoded_csr,
            "certificate": decoded_certificate,
            "ca-certificate": decoded_ca_certificate,
            "ca-chain": decoded_ca_chain,
            # SCENARIO-NOTE: it seems like this would be more natural as `relation.id`?
            "relation-id": relation.relation_id,
        },
    )
    # SCENARIO-NOTE: in the docs, 'out' is used as a name here, but also for
    # the return value of `ctx.run(...)`. Maybe different names would be better,
    # given that it's really `out.state` that's the `run_action()` equivilent?
    out = ctx.run_action(action, state=state)
    assert out.success
    assert out.results["result"] == "Certificates successfully provided."
    # SCENARIO-NOTE: My first instance here was to get the data from the relation
    # object I already had, and it took a moment to remember that it's immutable
    # and I needed to get the new state of the relation via out.state. That
    # might just be getting familiar with Scenario, though?
    certificate = json.loads(out.state.relations[0].local_app_data["certificates"])[0]
    assert certificate["ca"] == certificates["ca_certificate"]
    assert certificate["certificate_signing_request"] == csr_from_file
    # There's probably a nicer way to do this.
    chain = [
        cert + "\n-----END CERTIFICATE-----"
        for cert in certificates["ca_chain"].split("\n-----END CERTIFICATE-----\n")
        if cert
    ]
    assert certificate["chain"] == chain
    assert certificate["certificate"] == certificates["certificate"]
    assert out.state.unit_status == ops.ActiveStatus("No outstanding requests.")


# SCENARIO-NOTE: This test doesn't work with Scenario, because the relation
# needs to exist for part of the action execution (if it's not set up at all
# that's covered by a different test above), but then not be present when it
# is time to add the certificate to the relation data. Perhaps that means this
# isn't something that needs to be tested, or even that the handling in the code
# isn't really required?
@pytest.mark.skip("Unsuitable for Scenario")
def test_given_runtime_error_during_set_relation_certificate_when_provide_certificate_action_then_event_fails(  # noqa: E501
    certificates,
):
    decoded_csr = certificates["decoded_csr"]
    decoded_certificate = certificates["decoded_certificate"]
    decoded_ca_certificate = certificates["decoded_ca_certificate"]
    decoded_ca_chain = certificates["decoded_ca_chain"]
    csr_from_file = get_certificate_from_file(filename="tests/csr.pem")
    ctx = scenario.Context(ManualTLSCertificatesCharm)
    relation = scenario.Relation(
        # SCENARIO-NOTE: 'endpoint' is an unfamiliar name to me in this context.
        endpoint="certificates",
        remote_app_name="requirer",
        remote_units_data={
            0: {
                "certificate_signing_requests": json.dumps(
                    [{"certificate_signing_request": csr_from_file}]
                )
            }
        },
    )
    state = scenario.State(relations=[], leader=True)
    action = scenario.Action(
        "provide-certificate",
        params={
            "certificate-signing-request": decoded_csr,
            "certificate": decoded_certificate,
            "ca-certificate": decoded_ca_certificate,
            "ca-chain": decoded_ca_chain,
            # SCENARIO-NOTE: it seems like this would be more natural as `relation.id`?
            "relation-id": relation.relation_id,
        },
    )
    out = ctx.run_action(action, state=state)
    assert not out.success
    assert out.failure == "Relation does not exist with the provided id."
