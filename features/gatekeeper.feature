Feature: Gatekeeper approvals
  As a gadget owner
  I want side-effecting actions to require my approval
  So that no agent or collaborator can act on external services without my consent

  Scenario: Side-effecting actions are queued, not executed
    Given user "alice" owns a notes gadget "g-gate"
    When alice asks the gatekeeper to "post" to "twitter" with payload "hello world"
    Then the action is queued as "pending"
    And the audit log contains "gatekeeper.request"

  Scenario: The owner can approve a pending action
    Given user "alice" owns a notes gadget "g-gate2"
    And alice requests approval to "post" to "slack" with payload "ship it"
    When alice approves the pending request
    Then the approval state is "approved"

  Scenario: A non-owner cannot approve an action
    Given user "alice" owns a notes gadget "g-gate3"
    And alice requests approval to "post" to "slack" with payload "ship it"
    When mallory tries to approve the pending request
    Then the platform denies access with status 403
