import asyncio

from _common import service_factory

from pykeycloak.factories import KeycloakServiceFactory


async def main():
    factory: KeycloakServiceFactory = await service_factory()

    # Get all policies
    policies = await factory.auth_policy.get_policies_async()
    print(f"Policies: {policies}")

    # Get all policies raw
    policies_raw = await factory.auth_policy.get_policies_raw_async()
    print(f"Policies raw: {policies_raw}")

    # NOTE: The following examples show the structure for creating policies,
    # but require existing role and policy IDs in your Keycloak instance.
    # Since we don't have specific IDs available in this example, these are commented out.
    # To use these, replace placeholder IDs with actual IDs from your Keycloak instance.

    # Example of creating a role-based policy
    # role_policy_payload = RolePolicyPayload(
    #     name="test-role-policy",
    #     type="role",
    #     logic="POSITIVE",  # or "NEGATIVE"
    #     decisionStrategy="UNANIMOUS",  # or "AFFIRMATIVE", "CONSENSUS"
    #     roles=[{
    #         "id": "YOUR_ROLE_ID_HERE",
    #         "required": True
    #     }]
    # )
    #
    # created_policy = await factory.policies.create_policy_role_async(
    #     payload=role_policy_payload
    # )
    # print(f"Created role policy: {created_policy}")

    # Example of creating a generic policy
    # generic_policy_payload = PermissionPayload(
    #     name="test-generic-policy",
    #     type="aggregate",  # or other policy types
    #     logic="POSITIVE",
    #     decisionStrategy="UNANIMOUS",
    #     policies=["YOUR_POLICY_ID_1_HERE", "YOUR_POLICY_ID_2_HERE"]  # IDs of other policies
    # )
    #
    # created_generic_policy = await factory.policies.create_policy_async(
    #     payload=generic_policy_payload
    # )
    # print(f"Created generic policy: {created_generic_policy}")

    # Example of getting policy by name
    # policies_by_name = await factory.policies.get_policy_by_name_async()
    # print(f"Policies by name: {policies_by_name}")

    # Example of getting associated policies
    # This requires an existing policy ID
    # if policies_raw and isinstance(policies_raw, list) and len(policies_raw) > 0:
    #     first_policy = policies_raw[0]
    #     if isinstance(first_policy, dict) and "id" in first_policy:
    #         policy_id = first_policy["id"]
    #         associated_policies = await factory.policies.get_associated_policies_async(
    #             policy_id=policy_id
    #         )
    #         print(f"Associated policies: {associated_policies}")

    # Example of deleting a policy
    # This requires an existing policy ID
    # if policies_raw and isinstance(policies_raw, list) and len(policies_raw) > 0:
    #     first_policy = policies_raw[0]
    #     if isinstance(first_policy, dict) and "id" in first_policy:
    #         policy_id = first_policy["id"]
    #         deleted_policy = await factory.policies.delete_policy_async(
    #             policy_id=policy_id
    #         )
    #         print(f"Deleted policy with ID: {policy_id}")


if __name__ == "__main__":
    asyncio.run(main())
