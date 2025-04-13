name: Default template
about: The default template for all issues
body:
  - type: markdown
    attributes:
      value: |
        Hi
  - type: checkboxes
    id: agreement
    attributes:
      label: Label
      description: abc
      options:
        - label: Orange cat
          required: true
