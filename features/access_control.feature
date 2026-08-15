Feature: Gadget access control
  As a gadget owner
  I want the platform to enforce who can open my gadget
  So that my data is only ever visible to people I choose

  Scenario: Owner can read and write their own gadget
    Given user "alice" owns a notes gadget "g-notes"
    When alice writes the note "title" with value "My secret"
    Then alice can read the note "title" and it equals "My secret"

  Scenario: A stranger cannot open a gadget they were not invited to
    Given user "alice" owns a notes gadget "g-private"
    When mallory tries to read the gadget "g-private"
    Then the platform denies access with status 403

  Scenario: An anonymous caller cannot open a gadget
    Given user "alice" owns a notes gadget "g-anon"
    When an anonymous caller tries to read the gadget "g-anon"
    Then the platform denies access with status 403

  Scenario: Sharing grants access, revoking removes it
    Given user "alice" owns a notes gadget "g-share"
    And alice shares the gadget "g-share" with "bob" as "viewer"
    When bob reads the gadget "g-share"
    Then bob can see the data
    And alice revokes "bob" from the gadget "g-share"
    When bob tries to read the gadget "g-share"
    Then the platform denies access with status 403

  Scenario: A viewer cannot write to a gadget
    Given user "alice" owns a notes gadget "g-view"
    And alice shares the gadget "g-view" with "bob" as "viewer"
    When bob tries to write the note "title" with value "hacked"
    Then the platform denies access with status 403
